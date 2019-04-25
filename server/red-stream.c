/* -*- Mode: C; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
   Copyright (C) 2009, 2013 Red Hat, Inc.

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <netinet/tcp.h>

#include <glib.h>

#include <openssl/err.h>

#include <common/log.h>

#include "main-dispatcher.h"
#include "net-utils.h"
#include "red-common.h"
#include "red-stream.h"
#include "reds.h"

// compatibility for *BSD systems
#if !defined(TCP_CORK) && !defined(__APPLE__)
#define TCP_CORK TCP_NOPUSH
#endif

struct AsyncRead {
    void *opaque;
    uint8_t *now;
    uint8_t *end;
    AsyncReadDone done;
    AsyncReadError error;
};
typedef struct AsyncRead AsyncRead;

#if HAVE_SASL
#include <sasl/sasl.h>

typedef struct RedSASL {
    sasl_conn_t *conn;

    /* If we want to negotiate an SSF layer with client */
    int wantSSF :1;
    /* If we are now running the SSF layer */
    int runSSF :1;

    /*
     * Buffering encoded data to allow more clear data
     * to be stuffed onto the output buffer
     */
    const uint8_t *encoded;
    unsigned int encodedLength;
    unsigned int encodedOffset;

    SpiceBuffer inbuffer;
} RedSASL;
#endif

struct RedStreamPrivate {
    SSL *ssl;

#if HAVE_SASL
    RedSASL sasl;
#endif

    AsyncRead async_read;

    /* life time of info:
     * allocated when creating RedStream.
     * deallocated when main_dispatcher handles the SPICE_CHANNEL_EVENT_DISCONNECTED
     * event, either from same thread or by call back from main thread. */
    SpiceChannelEventInfo* info;
    bool use_cork;
    bool corked;

    ssize_t (*read)(RedStream *s, void *buf, size_t nbyte);
    ssize_t (*write)(RedStream *s, const void *buf, size_t nbyte);
    ssize_t (*writev)(RedStream *s, const struct iovec *iov, int iovcnt);

    RedsState *reds;
    SpiceCoreInterfaceInternal *core;
};

#if !defined(__APPLE__) // TCP_CORK doesn't exist and TCP_NOPUSH is broken
/**
 * Set TCP_CORK on socket
 */
/* NOTE: enabled must be int */
static int socket_set_cork(int socket, int enabled)
{
    SPICE_VERIFY(sizeof(enabled) == sizeof(int));
    return setsockopt(socket, IPPROTO_TCP, TCP_CORK, &enabled, sizeof(enabled));
}
#endif

static ssize_t stream_write_cb(RedStream *s, const void *buf, size_t size)
{
    return write(s->socket, buf, size);
}

static ssize_t stream_writev_cb(RedStream *s, const struct iovec *iov, int iovcnt)
{
    ssize_t ret = 0;
    do {
        int tosend;
        ssize_t n, expected = 0;
        int i;
#ifdef IOV_MAX
        tosend = MIN(iovcnt, IOV_MAX);
#else
        tosend = iovcnt;
#endif
        for (i = 0; i < tosend; i++) {
            expected += iov[i].iov_len;
        }
        n = writev(s->socket, iov, tosend);
        if (n <= expected) {
            if (n > 0)
                ret += n;
            return ret == 0 ? n : ret;
        }
        ret += n;
        iov += tosend;
        iovcnt -= tosend;
    } while(iovcnt > 0);

    return ret;
}

static ssize_t stream_read_cb(RedStream *s, void *buf, size_t size)
{
    return read(s->socket, buf, size);
}

static ssize_t stream_ssl_write_cb(RedStream *s, const void *buf, size_t size)
{
    int return_code;
    SPICE_GNUC_UNUSED int ssl_error;

    return_code = SSL_write(s->priv->ssl, buf, size);

    if (return_code < 0) {
        ssl_error = SSL_get_error(s->priv->ssl, return_code);
    }

    return return_code;
}

static ssize_t stream_ssl_read_cb(RedStream *s, void *buf, size_t size)
{
    int return_code;
    SPICE_GNUC_UNUSED int ssl_error;

    return_code = SSL_read(s->priv->ssl, buf, size);

    if (return_code < 0) {
        ssl_error = SSL_get_error(s->priv->ssl, return_code);
    }

    return return_code;
}

void red_stream_remove_watch(RedStream* s)
{
    if (s->watch) {
        s->priv->core->watch_remove(s->priv->core, s->watch);
        s->watch = NULL;
    }
}

#if HAVE_SASL
static ssize_t red_stream_sasl_read(RedStream *s, uint8_t *buf, size_t nbyte);
#endif

ssize_t red_stream_read(RedStream *s, void *buf, size_t nbyte)
{
    ssize_t ret;

#if HAVE_SASL
    if (s->priv->sasl.conn && s->priv->sasl.runSSF) {
        ret = red_stream_sasl_read(s, buf, nbyte);
    } else
#endif
        ret = s->priv->read(s, buf, nbyte);

    return ret;
}

bool red_stream_write_all(RedStream *stream, const void *in_buf, size_t n)
{
    const uint8_t *buf = (uint8_t *)in_buf;

    while (n) {
        int now = red_stream_write(stream, buf, n);
        if (now <= 0) {
            if (now == -1 && (errno == EINTR || errno == EAGAIN)) {
                continue;
            }
            return false;
        }
        n -= now;
        buf += now;
    }
    return true;
}

bool red_stream_set_auto_flush(RedStream *s, bool auto_flush)
{
#if !defined(__APPLE__)
    if (s->priv->use_cork == !auto_flush) {
        return true;
    }

    s->priv->use_cork = !auto_flush;
    if (s->priv->use_cork) {
        if (socket_set_cork(s->socket, 1)) {
            s->priv->use_cork = false;
            return false;
        } else {
            s->priv->corked = true;
        }
    } else if (s->priv->corked) {
        socket_set_cork(s->socket, 0);
        s->priv->corked = false;
    }
#endif
    return true;
}

void red_stream_flush(RedStream *s)
{
#if !defined(__APPLE__)
    if (s->priv->corked) {
        socket_set_cork(s->socket, 0);
        socket_set_cork(s->socket, 1);
    }
#endif
}

#if HAVE_SASL
static ssize_t red_stream_sasl_write(RedStream *s, const void *buf, size_t nbyte);
#endif

ssize_t red_stream_write(RedStream *s, const void *buf, size_t nbyte)
{
    ssize_t ret;

#if HAVE_SASL
    if (s->priv->sasl.conn && s->priv->sasl.runSSF) {
        ret = red_stream_sasl_write(s, buf, nbyte);
    } else
#endif
        ret = s->priv->write(s, buf, nbyte);

    return ret;
}

int red_stream_get_family(const RedStream *s)
{
    spice_return_val_if_fail(s != NULL, -1);

    if (s->socket == -1)
        return -1;

    return s->priv->info->laddr_ext.ss_family;
}

bool red_stream_is_plain_unix(const RedStream *s)
{
    spice_return_val_if_fail(s != NULL, false);

    if (red_stream_get_family(s) != AF_UNIX) {
        return false;
    }

#if HAVE_SASL
    if (s->priv->sasl.conn) {
        return false;
    }
#endif
    if (s->priv->ssl) {
        return false;
    }

    return true;

}

/**
 * red_stream_set_no_delay:
 * @stream: a #RedStream
 * @no_delay: whether to enable TCP_NODELAY on @@stream
 *
 * Returns: #true if the operation succeeded, #false otherwise.
 */
bool red_stream_set_no_delay(RedStream *stream, bool no_delay)
{
    return red_socket_set_no_delay(stream->socket, no_delay);
}

int red_stream_get_no_delay(RedStream *stream)
{
    return red_socket_get_no_delay(stream->socket);
}

int red_stream_send_msgfd(RedStream *stream, int fd)
{
    struct msghdr msgh = { 0, };
    struct iovec iov;
    int r;

    const size_t fd_size = 1 * sizeof(int);
    struct cmsghdr *cmsg;
    union {
        struct cmsghdr hdr;
        char data[CMSG_SPACE(fd_size)];
    } control;

    spice_return_val_if_fail(red_stream_is_plain_unix(stream), -1);

    /* set the payload */
    iov.iov_base = (char*)"@";
    iov.iov_len = 1;
    msgh.msg_iovlen = 1;
    msgh.msg_iov = &iov;

    if (fd != -1) {
        msgh.msg_control = control.data;
        msgh.msg_controllen = sizeof(control.data);
        /* CMSG_SPACE() might be larger than CMSG_LEN() as it can include some
         * padding. We set the whole control data to 0 to avoid valgrind warnings
         */
        memset(control.data, 0, sizeof(control.data));

        cmsg = CMSG_FIRSTHDR(&msgh);
        cmsg->cmsg_len = CMSG_LEN(fd_size);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        memcpy(CMSG_DATA(cmsg), &fd, fd_size);
    }

#if defined(__APPLE__)
    int set = 1;
    setsockopt(stream->socket, SOL_SOCKET, SO_NOSIGPIPE, (void *)&set, sizeof(int));
#endif
    do {
#if defined(__APPLE__)
        r = sendmsg(stream->socket, &msgh, 0);
#else
        r = sendmsg(stream->socket, &msgh, MSG_NOSIGNAL);
#endif
    } while (r < 0 && (errno == EINTR || errno == EAGAIN));

    return r;
}

ssize_t red_stream_writev(RedStream *s, const struct iovec *iov, int iovcnt)
{
    int i;
    int n;
    ssize_t ret = 0;

    if (s->priv->writev != NULL && iovcnt > 1) {
        return s->priv->writev(s, iov, iovcnt);
    }

    for (i = 0; i < iovcnt; ++i) {
        n = red_stream_write(s, iov[i].iov_base, iov[i].iov_len);
        if (n <= 0)
            return ret == 0 ? n : ret;
        ret += n;
    }

    return ret;
}

void red_stream_free(RedStream *s)
{
    if (!s) {
        return;
    }

    red_stream_push_channel_event(s, SPICE_CHANNEL_EVENT_DISCONNECTED);

#if HAVE_SASL
    if (s->priv->sasl.conn) {
        s->priv->sasl.runSSF = s->priv->sasl.wantSSF = 0;
        s->priv->sasl.encodedLength = s->priv->sasl.encodedOffset = 0;
        s->priv->sasl.encoded = NULL;
        sasl_dispose(&s->priv->sasl.conn);
        s->priv->sasl.conn = NULL;
    }
#endif

    if (s->priv->ssl) {
        SSL_free(s->priv->ssl);
    }

    red_stream_remove_watch(s);
    close(s->socket);

    g_free(s);
}

void red_stream_push_channel_event(RedStream *s, int event)
{
    RedsState *reds = s->priv->reds;
    MainDispatcher *md = reds_get_main_dispatcher(reds);
    main_dispatcher_channel_event(md, event, s->priv->info);
}

static void red_stream_set_socket(RedStream *stream, int socket)
{
    stream->socket = socket;
    /* deprecated fields. Filling them for backward compatibility */
    stream->priv->info->llen = sizeof(stream->priv->info->laddr);
    stream->priv->info->plen = sizeof(stream->priv->info->paddr);
    getsockname(stream->socket, (struct sockaddr*)(&stream->priv->info->laddr), &stream->priv->info->llen);
    getpeername(stream->socket, (struct sockaddr*)(&stream->priv->info->paddr), &stream->priv->info->plen);

    stream->priv->info->flags |= SPICE_CHANNEL_EVENT_FLAG_ADDR_EXT;
    stream->priv->info->llen_ext = sizeof(stream->priv->info->laddr_ext);
    stream->priv->info->plen_ext = sizeof(stream->priv->info->paddr_ext);
    getsockname(stream->socket, (struct sockaddr*)(&stream->priv->info->laddr_ext),
                &stream->priv->info->llen_ext);
    getpeername(stream->socket, (struct sockaddr*)(&stream->priv->info->paddr_ext),
                &stream->priv->info->plen_ext);
}


void red_stream_set_channel(RedStream *stream, int connection_id,
                            int channel_type, int channel_id)
{
    stream->priv->info->connection_id = connection_id;
    stream->priv->info->type = channel_type;
    stream->priv->info->id   = channel_id;
    if (red_stream_is_ssl(stream)) {
        stream->priv->info->flags |= SPICE_CHANNEL_EVENT_FLAG_TLS;
    }
}

RedStream *red_stream_new(RedsState *reds, int socket)
{
    RedStream *stream;

    stream = g_malloc0(sizeof(RedStream) + sizeof(RedStreamPrivate));
    stream->priv = (RedStreamPrivate *)(stream+1);
    stream->priv->info = g_new0(SpiceChannelEventInfo, 1);
    stream->priv->reds = reds;
    stream->priv->core = reds_get_core_interface(reds);
    red_stream_set_socket(stream, socket);

    stream->priv->read = stream_read_cb;
    stream->priv->write = stream_write_cb;
    stream->priv->writev = stream_writev_cb;

    return stream;
}

void red_stream_set_core_interface(RedStream *stream, SpiceCoreInterfaceInternal *core)
{
    red_stream_remove_watch(stream);
    stream->priv->core = core;
}

bool red_stream_is_ssl(RedStream *stream)
{
    return (stream->priv->ssl != NULL);
}

static void red_stream_disable_writev(RedStream *stream)
{
    stream->priv->writev = NULL;
}

RedStreamSslStatus red_stream_ssl_accept(RedStream *stream)
{
    int ssl_error;
    int return_code;

    return_code = SSL_accept(stream->priv->ssl);
    if (return_code == 1) {
        return RED_STREAM_SSL_STATUS_OK;
    }

    ssl_error = SSL_get_error(stream->priv->ssl, return_code);
    if (return_code == -1 && (ssl_error == SSL_ERROR_WANT_READ ||
                              ssl_error == SSL_ERROR_WANT_WRITE)) {
        if (ssl_error == SSL_ERROR_WANT_READ) {
            return RED_STREAM_SSL_STATUS_WAIT_FOR_READ;
        } else {
            return RED_STREAM_SSL_STATUS_WAIT_FOR_WRITE;
        }
    }

    ERR_print_errors_fp(stderr);
    spice_warning("SSL_accept failed, error=%d", ssl_error);
    SSL_free(stream->priv->ssl);
    stream->priv->ssl = NULL;

    return RED_STREAM_SSL_STATUS_ERROR;
}

int red_stream_enable_ssl(RedStream *stream, SSL_CTX *ctx)
{
    BIO *sbio;

    // Handle SSL handshaking
    if (!(sbio = BIO_new_socket(stream->socket, BIO_NOCLOSE))) {
        spice_warning("could not allocate ssl bio socket");
        return RED_STREAM_SSL_STATUS_ERROR;
    }

    stream->priv->ssl = SSL_new(ctx);
    if (!stream->priv->ssl) {
        spice_warning("could not allocate ssl context");
        BIO_free(sbio);
        return RED_STREAM_SSL_STATUS_ERROR;
    }

    SSL_set_bio(stream->priv->ssl, sbio, sbio);

    stream->priv->write = stream_ssl_write_cb;
    stream->priv->read = stream_ssl_read_cb;
    red_stream_disable_writev(stream);

    return red_stream_ssl_accept(stream);
}

void red_stream_set_async_error_handler(RedStream *stream,
                                        AsyncReadError error_handler)
{
    stream->priv->async_read.error = error_handler;
}

static inline void async_read_clear_handlers(RedStream *stream)
{
    AsyncRead *async = &stream->priv->async_read;
    red_stream_remove_watch(stream);
    async->now = NULL;
    async->end = NULL;
}

static void async_read_handler(G_GNUC_UNUSED int fd,
                               G_GNUC_UNUSED int event,
                               void *data)
{
    RedStream *stream = data;
    AsyncRead *async = &stream->priv->async_read;
    SpiceCoreInterfaceInternal *core = stream->priv->core;

    for (;;) {
        int n = async->end - async->now;

        spice_assert(n > 0);
        n = red_stream_read(stream, async->now, n);
        if (n <= 0) {
            int err = n < 0 ? errno: 0;
            switch (err) {
            case EAGAIN:
                if (!stream->watch) {
                    stream->watch = core->watch_add(core, stream->socket,
                                                    SPICE_WATCH_EVENT_READ,
                                                    async_read_handler, stream);
                }
                return;
            case EINTR:
                break;
            default:
                async_read_clear_handlers(stream);
                if (async->error) {
                    async->error(async->opaque, err);
                }
                return;
            }
        } else {
            async->now += n;
            if (async->now == async->end) {
                async_read_clear_handlers(stream);
                async->done(async->opaque);
                return;
            }
        }
    }
}

void red_stream_async_read(RedStream *stream,
                           uint8_t *data, size_t size,
                           AsyncReadDone read_done_cb,
                           void *opaque)
{
    AsyncRead *async = &stream->priv->async_read;

    g_return_if_fail(async->now == NULL && async->end == NULL);
    if (size == 0) {
        read_done_cb(opaque);
        return;
    }
    async->now = data;
    async->end = async->now + size;
    async->done = read_done_cb;
    async->opaque = opaque;
    async_read_handler(0, 0, stream);

}

#if HAVE_SASL
static bool red_stream_write_u8(RedStream *s, uint8_t n)
{
    return red_stream_write_all(s, &n, sizeof(uint8_t));
}

static bool red_stream_write_u32_le(RedStream *s, uint32_t n)
{
    n = GUINT32_TO_LE(n);
    return red_stream_write_all(s, &n, sizeof(uint32_t));
}

static ssize_t red_stream_sasl_write(RedStream *s, const void *buf, size_t nbyte)
{
    ssize_t ret;

    if (!s->priv->sasl.encoded) {
        int err;
        err = sasl_encode(s->priv->sasl.conn, (char *)buf, nbyte,
                          (const char **)&s->priv->sasl.encoded,
                          &s->priv->sasl.encodedLength);
        if (err != SASL_OK) {
            spice_warning("sasl_encode error: %d", err);
            errno = EIO;
            return -1;
        }

        if (s->priv->sasl.encodedLength == 0) {
            return 0;
        }

        if (!s->priv->sasl.encoded) {
            spice_warning("sasl_encode didn't return a buffer!");
            return 0;
        }

        s->priv->sasl.encodedOffset = 0;
    }

    ret = s->priv->write(s, s->priv->sasl.encoded + s->priv->sasl.encodedOffset,
                         s->priv->sasl.encodedLength - s->priv->sasl.encodedOffset);

    if (ret <= 0) {
        return ret;
    }

    s->priv->sasl.encodedOffset += ret;
    if (s->priv->sasl.encodedOffset == s->priv->sasl.encodedLength) {
        s->priv->sasl.encoded = NULL;
        s->priv->sasl.encodedOffset = s->priv->sasl.encodedLength = 0;
        return nbyte;
    }

    /* we didn't flush the encoded buffer */
    errno = EAGAIN;
    return -1;
}

static ssize_t red_stream_sasl_read(RedStream *s, uint8_t *buf, size_t nbyte)
{
    uint8_t encoded[4096];
    const char *decoded;
    unsigned int decodedlen;
    int err;
    int n;

    n = spice_buffer_copy(&s->priv->sasl.inbuffer, buf, nbyte);
    if (n > 0) {
        spice_buffer_remove(&s->priv->sasl.inbuffer, n);
        if (n == nbyte)
            return n;
        nbyte -= n;
        buf += n;
    }

    n = s->priv->read(s, encoded, sizeof(encoded));
    if (n <= 0) {
        return n;
    }

    err = sasl_decode(s->priv->sasl.conn,
                      (char *)encoded, n,
                      &decoded, &decodedlen);
    if (err != SASL_OK) {
        spice_warning("sasl_decode error: %d", err);
        errno = EIO;
        return -1;
    }

    if (decodedlen == 0) {
        errno = EAGAIN;
        return -1;
    }

    n = MIN(nbyte, decodedlen);
    memcpy(buf, decoded, n);
    spice_buffer_append(&s->priv->sasl.inbuffer, decoded + n, decodedlen - n);
    return n;
}

static char *addr_to_string(const char *format,
                            struct sockaddr_storage *sa,
                            socklen_t salen)
{
    char host[NI_MAXHOST];
    char serv[NI_MAXSERV];
    int err;

    if ((err = getnameinfo((struct sockaddr *)sa, salen,
                           host, sizeof(host),
                           serv, sizeof(serv),
                           NI_NUMERICHOST | NI_NUMERICSERV)) != 0) {
        spice_warning("Cannot resolve address %d: %s",
                      err, gai_strerror(err));
        return NULL;
    }

    return g_strdup_printf(format, host, serv);
}

static char *red_stream_get_local_address(RedStream *stream)
{
    return addr_to_string("%s;%s", &stream->priv->info->laddr_ext,
                          stream->priv->info->llen_ext);
}

static char *red_stream_get_remote_address(RedStream *stream)
{
    return addr_to_string("%s;%s", &stream->priv->info->paddr_ext,
                          stream->priv->info->plen_ext);
}

static int auth_sasl_check_ssf(RedSASL *sasl, int *runSSF)
{
    const void *val;
    int err, ssf;

    *runSSF = 0;
    if (!sasl->wantSSF) {
        return 1;
    }

    err = sasl_getprop(sasl->conn, SASL_SSF, &val);
    if (err != SASL_OK) {
        return 0;
    }

    ssf = *(const int *)val;
    spice_debug("negotiated an SSF of %d", ssf);
    if (ssf < 56) {
        return 0; /* 56 is good for Kerberos */
    }

    *runSSF = 1;

    /* We have a SSF that's good enough */
    return 1;
}

typedef struct RedSASLAuth {
    RedStream *stream;
    // list of mechanisms allowed, allocated and freed by SASL
    char *mechlist;
    // mech received
    char *mechname;
    uint32_t len;
    char *data;
    // callback to call if success
    RedSaslResult result_cb;
    void *result_opaque;
    // saved Async callback, we need to call if failed as
    // we need to chain it in order to use a different opaque data
    AsyncReadError saved_error_cb;
} RedSASLAuth;

static void red_sasl_auth_free(RedSASLAuth *auth)
{
    g_free(auth->data);
    g_free(auth->mechname);
    g_free(auth->mechlist);
    g_free(auth);
}

// handle SASL termination, either success or error
// NOTE: After this function is called usually there should be a
// return or the function should exit
static void red_sasl_async_result(RedSASLAuth *auth, RedSaslError err)
{
    red_stream_set_async_error_handler(auth->stream, auth->saved_error_cb);
    auth->result_cb(auth->result_opaque, err);
    red_sasl_auth_free(auth);
}

static void red_sasl_error(void *opaque, int err)
{
    RedSASLAuth *auth = opaque;
    red_stream_set_async_error_handler(auth->stream, auth->saved_error_cb);
    if (auth->saved_error_cb) {
        auth->saved_error_cb(auth->result_opaque, err);
    }
    red_sasl_auth_free(auth);
}

/*
 * Step Msg
 *
 * Input from client:
 *
 * u32 clientin-length
 * u8-array clientin-string
 *
 * Output to client:
 *
 * u32 serverout-length
 * u8-array serverout-strin
 * u8 continue
 */
#define SASL_MAX_MECHNAME_LEN 100
#define SASL_DATA_MAX_LEN (1024 * 1024)

static void red_sasl_handle_auth_steplen(void *opaque);

/*
 * Start Msg
 *
 * Input from client:
 *
 * u32 clientin-length
 * u8-array clientin-string
 *
 * Output to client:
 *
 * u32 serverout-length
 * u8-array serverout-strin
 * u8 continue
 */

static void red_sasl_handle_auth_step(void *opaque)
{
    RedSASLAuth *auth = opaque;
    RedStream *stream = auth->stream;
    const char *serverout;
    unsigned int serveroutlen;
    int err;
    char *clientdata = NULL;
    RedSASL *sasl = &stream->priv->sasl;
    uint32_t datalen = auth->len;

    /* NB, distinction of NULL vs "" is *critical* in SASL */
    if (datalen) {
        clientdata = auth->data;
        clientdata[datalen - 1] = '\0'; /* Wire includes '\0', but make sure */
        datalen--; /* Don't count NULL byte when passing to _start() */
    }

    if (auth->mechname != NULL) {
        spice_debug("Start SASL auth with mechanism %s. Data %p (%d bytes)",
                    auth->mechname, clientdata, datalen);
        err = sasl_server_start(sasl->conn,
                                auth->mechname,
                                clientdata,
                                datalen,
                                &serverout,
                                &serveroutlen);
        g_free(auth->mechname);
        auth->mechname = NULL;
    } else {
        spice_debug("Step using SASL Data %p (%d bytes)", clientdata, datalen);
        err = sasl_server_step(sasl->conn,
                               clientdata,
                               datalen,
                               &serverout,
                               &serveroutlen);
    }
    if (err != SASL_OK &&
        err != SASL_CONTINUE) {
        spice_warning("sasl step failed %d (%s)",
                    err, sasl_errdetail(sasl->conn));
        return red_sasl_async_result(auth, RED_SASL_ERROR_GENERIC);
    }

    if (serveroutlen > SASL_DATA_MAX_LEN) {
        spice_warning("sasl step reply data too long %d",
                      serveroutlen);
        return red_sasl_async_result(auth, RED_SASL_ERROR_GENERIC);
    }

    spice_debug("SASL return data %d bytes, %p", serveroutlen, serverout);

    if (serveroutlen) {
        serveroutlen += 1;
        red_stream_write_u32_le(stream, serveroutlen);
        red_stream_write_all(stream, serverout, serveroutlen);
    } else {
        red_stream_write_u32_le(stream, serveroutlen);
    }

    /* Whether auth is complete */
    red_stream_write_u8(stream, err == SASL_CONTINUE ? 0 : 1);

    if (err == SASL_CONTINUE) {
        spice_debug("%s", "Authentication must continue");
        /* Wait for step length */
        red_stream_async_read(stream, (uint8_t *)&auth->len, sizeof(uint32_t),
                              red_sasl_handle_auth_steplen, auth);
        return;
    } else {
        int ssf;

        if (auth_sasl_check_ssf(sasl, &ssf) == 0) {
            spice_warning("Authentication rejected for weak SSF");
            goto authreject;
        }

        spice_debug("Authentication successful");
        red_stream_write_u32_le(stream, SPICE_LINK_ERR_OK); /* Accept auth */

        /*
         * Delay writing in SSF encoded until now
         */
        sasl->runSSF = ssf;
        red_stream_disable_writev(stream); /* make sure writev isn't called directly anymore */

        return red_sasl_async_result(auth, RED_SASL_ERROR_OK);
    }

authreject:
    red_stream_write_u32_le(stream, 1); /* Reject auth */
    red_stream_write_u32_le(stream, sizeof("Authentication failed"));
    red_stream_write_all(stream, "Authentication failed", sizeof("Authentication failed"));

    red_sasl_async_result(auth, RED_SASL_ERROR_AUTH_FAILED);
}

static void red_sasl_handle_auth_steplen(void *opaque)
{
    RedSASLAuth *auth = opaque;

    auth->len = GUINT32_FROM_LE(auth->len);
    uint32_t len = auth->len;
    spice_debug("Got steplen %d", len);
    if (len > SASL_DATA_MAX_LEN) {
        spice_warning("Too much SASL data %d", len);
        return red_sasl_async_result(opaque, auth->mechname ? RED_SASL_ERROR_INVALID_DATA : RED_SASL_ERROR_GENERIC);
    }

    auth->data = g_realloc(auth->data, len);
    red_stream_async_read(auth->stream, (uint8_t *)auth->data, len,
                          red_sasl_handle_auth_step, auth);
}



static void red_sasl_handle_auth_mechname(void *opaque)
{
    RedSASLAuth *auth = opaque;

    auth->mechname[auth->len] = '\0';
    spice_debug("Got client mechname '%s' check against '%s'",
                auth->mechname, auth->mechlist);

    char quoted_mechname[SASL_MAX_MECHNAME_LEN + 4];
    sprintf(quoted_mechname, ",%s,", auth->mechname);

    if (strchr(auth->mechname, ',') || strstr(auth->mechlist, quoted_mechname) == NULL) {
        return red_sasl_async_result(auth, RED_SASL_ERROR_INVALID_DATA);
    }

    spice_debug("Validated mechname '%s'", auth->mechname);

    red_stream_async_read(auth->stream, (uint8_t *)&auth->len, sizeof(uint32_t),
                          red_sasl_handle_auth_steplen, auth);
}

static void red_sasl_handle_auth_mechlen(void *opaque)
{
    RedSASLAuth *auth = opaque;

    auth->len = GUINT32_FROM_LE(auth->len);
    uint32_t len = auth->len;
    if (len < 1 || len > SASL_MAX_MECHNAME_LEN) {
        spice_warning("Got bad client mechname len %d", len);
        return red_sasl_async_result(auth, RED_SASL_ERROR_GENERIC);
    }

    auth->mechname = g_malloc(len + 1);

    spice_debug("Wait for client mechname");
    red_stream_async_read(auth->stream, (uint8_t *)auth->mechname, len,
                          red_sasl_handle_auth_mechname, auth);
}

bool red_sasl_start_auth(RedStream *stream, RedSaslResult result_cb, void *result_opaque)
{
    const char *mechlist = NULL;
    sasl_security_properties_t secprops;
    int err;
    char *localAddr, *remoteAddr;
    int mechlistlen;
    RedSASL *sasl = &stream->priv->sasl;
    RedSASLAuth *auth;

    if (!(localAddr = red_stream_get_local_address(stream))) {
        goto error;
    }

    if (!(remoteAddr = red_stream_get_remote_address(stream))) {
        g_free(localAddr);
        goto error;
    }

    err = sasl_server_new("spice",
                          NULL, /* FQDN - just delegates to gethostname */
                          NULL, /* User realm */
                          localAddr,
                          remoteAddr,
                          NULL, /* Callbacks, not needed */
                          SASL_SUCCESS_DATA,
                          &sasl->conn);
    g_free(localAddr);
    g_free(remoteAddr);
    localAddr = remoteAddr = NULL;

    if (err != SASL_OK) {
        spice_warning("sasl context setup failed %d (%s)",
                    err, sasl_errstring(err, NULL, NULL));
        sasl->conn = NULL;
        goto error;
    }

    /* Inform SASL that we've got an external SSF layer from TLS */
    if (stream->priv->ssl) {
        sasl_ssf_t ssf;

        ssf = SSL_get_cipher_bits(stream->priv->ssl, NULL);
        err = sasl_setprop(sasl->conn, SASL_SSF_EXTERNAL, &ssf);
        if (err != SASL_OK) {
            spice_warning("cannot set SASL external SSF %d (%s)",
                        err, sasl_errstring(err, NULL, NULL));
            goto error_dispose;
        }
    } else {
        sasl->wantSSF = 1;
    }

    memset(&secprops, 0, sizeof secprops);
    /* Inform SASL that we've got an external SSF layer from TLS */
    if (stream->priv->ssl) {
        /* If we've got TLS (or UNIX domain sock), we don't care about SSF */
        secprops.min_ssf = 0;
        secprops.max_ssf = 0;
        secprops.maxbufsize = 8192;
        secprops.security_flags = 0;
    } else {
        /* Plain TCP, better get an SSF layer */
        secprops.min_ssf = 56; /* Good enough to require kerberos */
        secprops.max_ssf = 100000; /* Arbitrary big number */
        secprops.maxbufsize = 8192;
        /* Forbid any anonymous or trivially crackable auth */
        secprops.security_flags =
            SASL_SEC_NOANONYMOUS | SASL_SEC_NOPLAINTEXT;
    }

    err = sasl_setprop(sasl->conn, SASL_SEC_PROPS, &secprops);
    if (err != SASL_OK) {
        spice_warning("cannot set SASL security props %d (%s)",
                      err, sasl_errstring(err, NULL, NULL));
        goto error_dispose;
    }

    err = sasl_listmech(sasl->conn,
                        NULL, /* Don't need to set user */
                        ",", /* Prefix */
                        ",", /* Separator */
                        ",", /* Suffix */
                        &mechlist,
                        NULL,
                        NULL);
    if (err != SASL_OK || mechlist == NULL) {
        spice_warning("cannot list SASL mechanisms %d (%s)",
                      err, sasl_errdetail(sasl->conn));
        goto error_dispose;
    }

    spice_debug("Available mechanisms for client: '%s'", mechlist);

    mechlistlen = strlen(mechlist);
    if (!red_stream_write_u32_le(stream, mechlistlen)
        || !red_stream_write_all(stream, mechlist, mechlistlen)) {
        spice_warning("SASL mechanisms write error");
        goto error;
    }

    auth = g_new0(RedSASLAuth, 1);
    auth->stream = stream;
    auth->result_cb = result_cb;
    auth->result_opaque = result_opaque;
    auth->saved_error_cb = stream->priv->async_read.error;
    auth->mechlist = g_strdup(mechlist);

    spice_debug("Wait for client mechname length");
    red_stream_set_async_error_handler(stream, red_sasl_error);
    red_stream_async_read(stream, (uint8_t *)&auth->len, sizeof(uint32_t),
                          red_sasl_handle_auth_mechlen, auth);

    return true;

error_dispose:
    sasl_dispose(&sasl->conn);
    sasl->conn = NULL;
error:
    return false;
}
#endif
