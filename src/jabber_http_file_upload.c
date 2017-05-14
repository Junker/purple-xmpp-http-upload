#define PURPLE_PLUGINS

#include <glib.h>

#include <stdlib.h>
#include <string.h>
#include <glib/gi18n.h>
#include <errno.h>

#include "cmds.h"
#include "debug.h"
#include "notify.h"
#include "plugin.h"
#include "version.h"
#include "sslconn.h"
#include "util.h"
#include "prpl.h"

#include "jutil.h"
#include "chat.h"
#include "ft.h"
#include "iq.h"
#include "disco.h"

#include "hfu_disco.h"
#include "hfu_util.h"
#include "jabber_http_file_upload.h"

GList *(*old_blist_node_menu)(PurpleBlistNode *node);

typedef struct {
    gchar *host;
    gint port;
    gchar *path;
    gchar *user;
    gchar *passwd;
} PurpleHttpURL;


static inline PurpleHttpURL *purple_http_url_parse(const gchar *url) {
    PurpleHttpURL *ret = g_new0(PurpleHttpURL, 1);
    purple_url_parse(url, &(ret->host), &(ret->port), &(ret->path), &(ret->user), &(ret->passwd));
    return ret;
}

#define purple_http_url_get_host(httpurl) (httpurl->host)
#define purple_http_url_get_port(httpurl) (httpurl->port)
#define purple_http_url_get_path(httpurl) (httpurl->path)
static inline void purple_http_url_free(PurpleHttpURL *phl) { g_free(phl->host); g_free(phl->path); g_free(phl->user); g_free(phl->passwd); g_free(phl);  }

#define PREF_PREFIX     "/plugins/xmpp-http-upload"
#define JABBER_PLUGIN_ID "prpl-jabber"


static void jabber_hfu_http_read(gpointer user_data, PurpleSslConnection *ssl_connection, PurpleInputCondition cond)
{
    gchar buf[1024];

    //Flush the server buffer
    purple_ssl_read(ssl_connection, buf, 1024);
    purple_debug_info("jabber_http_upload", "Server file send response was %s\n", buf);
}

static void jabber_hfu_http_send_connect_cb(gpointer data, PurpleSslConnection *ssl_connection, PurpleInputCondition cond)
{
    PurpleHttpURL *httpurl;
    gchar *headers, *host, *path;

    PurpleXfer *xfer = data;
    HFUXfer *hfux = purple_xfer_get_protocol_data(xfer);
    HFUJabberStreamData *js_data = hfux->js_data;

    httpurl = purple_http_url_parse(hfux->put_url);
    path = purple_http_url_get_path(httpurl);

    if (str_equal(js_data->ns, NS_HTTP_FILE_UPLOAD_V0))
        host = g_hash_table_lookup(hfux->put_headers, "Host") ?: purple_http_url_get_host(httpurl);
    else
        host = purple_http_url_get_host(httpurl);
    
 
    headers = g_strdup_printf("PUT /%s HTTP/1.0\r\n"
            "Connection: close\r\n"
            "Host: %s\r\n"
            "Content-Length: %lu\r\n"
            "Content-Type: application/octet-stream\r\n"
            "User-Agent: libpurple\r\n"
            "\r\n",
            path,
            host,
            purple_xfer_get_size(xfer));

    //add headers!!!

    purple_ssl_write(ssl_connection, headers, strlen(headers));

    hfux->ssl_conn = ssl_connection;
    purple_ssl_input_add(ssl_connection, jabber_hfu_http_read, xfer);

    purple_xfer_ref(xfer);
    purple_xfer_start(xfer, ssl_connection->fd, NULL, 0);

    purple_xfer_prpl_ready(xfer);

    g_free(headers);

}

static void jabber_hfu_http_error_connect_cb(PurpleSslConnection *ssl_connection, PurpleSslErrorType *error_type, gpointer data)
{
    purple_debug_info("jabber_http_upload", "SSL error\n");
}

static void jabber_hfu_request_cb(JabberStream *js, const char *from,
                                          JabberIqType type, const char *id,
                                          xmlnode *packet, gpointer data)
{
    PurpleAccount *account;
    xmlnode *slot, *put, *get, *header = NULL;
    PurpleHttpURL *put_httpurl;
    gchar *put_host;

    PurpleXfer *xfer = data;
    HFUXfer *hfux = purple_xfer_get_protocol_data(xfer);
    HFUJabberStreamData *js_data = hfux->js_data;
    account = purple_connection_get_account(js->gc);

    if(!(slot = xmlnode_get_child_with_namespace(packet, "slot", js_data->ns)))
    {
        purple_xfer_cancel_remote(xfer);
        return;
    }

    put = xmlnode_get_child(slot, "put");
    get = xmlnode_get_child(slot, "get");

    if (str_equal(js_data->ns, NS_HTTP_FILE_UPLOAD_V0))
    {
        hfux->put_headers = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
        for (header = xmlnode_get_child(put, "header") ; header;
                 header = xmlnode_get_next_twin(header))
        {
            g_hash_table_insert(hfux->put_headers, g_strdup(xmlnode_get_attrib(header, "name")), g_strdup(xmlnode_get_data(header)));
        }

        hfux->put_url = g_strdup(xmlnode_get_attrib(put, "url"));
        hfux->get_url = g_strdup(xmlnode_get_attrib(get, "url"));
    }
    else
    {
        hfux->put_url = xmlnode_get_data(put);
        hfux->get_url = xmlnode_get_data(get);
    }

    put_httpurl = purple_http_url_parse(hfux->put_url);
    put_host = purple_http_url_get_host(put_httpurl);

    purple_ssl_connect(account, put_host, purple_http_url_get_port(put_httpurl), jabber_hfu_http_send_connect_cb, (PurpleSslErrorFunction)jabber_hfu_http_error_connect_cb, xfer);

    purple_http_url_free(put_httpurl);
}

static void jabber_hfu_xfer_free(PurpleXfer *xfer)
{
    HFUXfer *hfux = purple_xfer_get_protocol_data(xfer);

    g_return_if_fail(hfux != NULL);

    if (hfux->put_url)
    {
        g_free(hfux->put_url);
    }

    if (hfux->get_url)
    {
        g_free(hfux->get_url);
    }

    if (hfux->ssl_conn)
    {
        purple_ssl_close(hfux->ssl_conn);
    }


    g_free(hfux);

    purple_xfer_set_protocol_data(xfer, NULL);
}


static void jabber_hfu_send_request(PurpleXfer *xfer)
{
    xmlnode *request_node;
    const gchar *filename, *filepath;
    gchar *filemime, *filesize;

    HFUXfer *hfux = purple_xfer_get_protocol_data(xfer);
    JabberStream *js = hfux->js;
    HFUJabberStreamData *js_data = hfux->js_data;

    JabberIq *iq = jabber_iq_new(js, JABBER_IQ_GET);

    xmlnode_set_attrib(iq->node, "to", js_data->host);

    request_node = xmlnode_new_child(iq->node, "request");
    xmlnode_set_namespace(request_node, js_data->ns);

    filename = purple_xfer_get_filename(xfer);
    filepath = purple_xfer_get_local_filename(xfer);
    filesize = g_strdup_printf("%lu", purple_xfer_get_size(xfer));
    filemime = file_get_mime(filepath);

    if (str_equal(js_data->ns, NS_HTTP_FILE_UPLOAD_V0))
    {
        xmlnode_set_attrib(request_node, "filename", filename);
        xmlnode_set_attrib(request_node, "size", filesize);

        if (filemime)
            xmlnode_set_attrib(request_node, "content-type", filemime);
    }
    else
    {
        xmlnode *filename_node = xmlnode_new_child(request_node, "filename");
        xmlnode_insert_data(filename_node, filename, -1);

        xmlnode *size_node = xmlnode_new_child(request_node, "size");
        xmlnode_insert_data(size_node, filesize, -1);

        if (filemime)
        {
            xmlnode *content_type_node = xmlnode_new_child(request_node, "content-type");
            xmlnode_insert_data(content_type_node, filemime, -1);
        }
    }

    jabber_iq_set_callback(iq, jabber_hfu_request_cb, xfer);
    jabber_iq_send(iq);

    g_free(filesize);

    if (filemime)
        g_free(filemime);
}


static void jabber_hfu_send_url_to_conv(PurpleXfer *xfer)
{
    PurpleConversation *conv;


    HFUXfer *hfux = purple_xfer_get_protocol_data(xfer);
    PurpleAccount *account = purple_xfer_get_account(xfer);
    PurpleConversationType conv_type;

    conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM, xfer->who, account);
    
    if (!conv)
    {
        conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_CHAT, xfer->who, account);
    }

    if (conv)
    {
        conv_type = purple_conversation_get_type(conv);

        if (conv_type == PURPLE_CONV_TYPE_CHAT)
        {
            PurpleConvChat *conv_chat = purple_conversation_get_chat_data(conv);
            purple_conv_chat_send(conv_chat, hfux->get_url);
        }
        else if (conv_type == PURPLE_CONV_TYPE_IM)
        {
            PurpleConvIm *conv_im = purple_conversation_get_im_data(conv);
            purple_conv_im_send(conv_im, hfux->get_url);
        }
    }
}

static void jabber_hfu_xfer_end(PurpleXfer *xfer)
{
    jabber_hfu_send_url_to_conv(xfer);

    jabber_hfu_xfer_free(xfer);
}


static void jabber_hfu_xfer_cancel_send(PurpleXfer *xfer)
{
    jabber_hfu_xfer_free(xfer);

    purple_debug_info("jabber_http_upload", "in jabber_hfu_xfer_cancel_send\n");
}

static gssize jabber_hfu_xfer_write(const guchar *buffer, size_t len, PurpleXfer *xfer)
{
    gssize tlen;

    HFUXfer *hfux = purple_xfer_get_protocol_data(xfer);

    tlen = purple_ssl_write(hfux->ssl_conn, buffer, len);

    if (tlen == -1) 
    {
        if (purple_xfer_get_bytes_sent(xfer) >= purple_xfer_get_size(xfer))
            purple_xfer_set_completed(xfer, TRUE);

        if ((errno != EAGAIN) && (errno != EINTR))
            return -1;

        return 0;
    }

    if ((purple_xfer_get_bytes_sent(xfer) + tlen) >= purple_xfer_get_size(xfer))
            purple_xfer_set_completed(xfer, TRUE);

    return tlen;
}

static void jabber_hfu_xfer_init(PurpleXfer *xfer)
{
    HFUXfer *hfux = purple_xfer_get_protocol_data(xfer);
    JabberStream *js = hfux->js;
    HFUJabberStreamData *js_data = g_hash_table_lookup(HFUJabberStreamDataTable, js);

    hfux->js_data = js_data;

    if (!js_data->ns)
    {
        purple_notify_error(hfux->js->gc, _("File Send Failed"), _("File Send Failed"), _("HTTP File Upload is not supported by server"));

        purple_debug_info("jabber_http_upload", "HTTP File Upload is not supported by server\n");
        purple_xfer_cancel_local(xfer);

        return;
    }

    if (js_data->max_file_size && purple_xfer_get_size(xfer) > js_data->max_file_size)
    {
        gchar *msg = g_strdup_printf(_("HTTP File Upload maximum file size is %lu bytes"), js_data->max_file_size);
        purple_notify_error(hfux->js->gc, _("File Send Failed"), _("File Send Failed"), msg);
        g_free(msg);

        purple_debug_info("jabber_http_upload", "HTTP File Upload maximum file size limit\n");
        purple_xfer_cancel_local(xfer);

        return;
    }

    jabber_hfu_send_request(xfer);
}



PurpleXfer *jabber_hfu_new_xfer(PurpleConnection *gc, const char *who)
{
    JabberStream *js;

    PurpleXfer *xfer;
    HFUXfer *hfux = NULL;

    js = gc->proto_data;

    xfer = purple_xfer_new(gc->account, PURPLE_XFER_SEND, who);

    purple_xfer_set_protocol_data(xfer, hfux = g_new0(HFUXfer, 1));
    hfux->js = js;

    purple_xfer_set_init_fnc(xfer, jabber_hfu_xfer_init);
    purple_xfer_set_cancel_send_fnc(xfer, jabber_hfu_xfer_cancel_send);
    purple_xfer_set_end_fnc(xfer, jabber_hfu_xfer_end);
    purple_xfer_set_write_fnc(xfer, jabber_hfu_xfer_write);

    return xfer;
}

void jabber_hfu_xfer_send(PurpleConnection *gc, const char *who, const char *filename)
{
    PurpleXfer *xfer;

    xfer = jabber_hfu_new_xfer(gc, who);

    if (filename && *filename)
        purple_xfer_request_accepted(xfer, filename);
    else
        purple_xfer_request(xfer);
}

static void jabber_hfu_signed_on_cb(PurpleConnection *conn, void *data)
{
    PurpleAccount *account = purple_connection_get_account(conn);

    if (strcmp(JABBER_PLUGIN_ID, purple_account_get_protocol_id(account)))
        return;

    JabberStream *js = purple_connection_get_protocol_data(conn);

    HFUJabberStreamData *js_data = g_new0(HFUJabberStreamData, 1);

    g_hash_table_insert(HFUJabberStreamDataTable, js, js_data);

    jabber_hfu_disco_items_server(js);
}

static void jabber_hfu_send_act(PurpleBlistNode *node, gpointer ignored)
{
    PurpleConnection *gc = NULL;
    const gchar *bname; 

    if(PURPLE_BLIST_NODE_IS_BUDDY(node))
    {
        PurpleBuddy *buddy = (PurpleBuddy *)node;
        gc = purple_account_get_connection(purple_buddy_get_account(buddy));

        bname = buddy->name;
    }
    else if (PURPLE_BLIST_NODE_IS_CHAT(node)) 
    {

        PurpleChat *chat = PURPLE_CHAT(node);
        gc = purple_account_get_connection(purple_chat_get_account(chat));

        bname = jabber_get_chat_name(purple_chat_get_components(chat));
    }

    if (gc)
        jabber_hfu_xfer_send(gc, bname, NULL);

}

static GList *jabber_hfu_blist_node_menu(PurpleBlistNode *node)
{
    PurpleMenuAction *act;

    GList *menu = old_blist_node_menu(node);

    act = purple_menu_action_new(_("HTTP File Upload"),
                PURPLE_CALLBACK(jabber_hfu_send_act),
                NULL, NULL);

    menu = g_list_append(menu, act);

    return menu;
}

gboolean plugin_unload(PurplePlugin *plugin)
{
    return TRUE;
}

gboolean plugin_load(PurplePlugin *plugin)
{
    PurplePlugin *jabber_plugin = purple_plugins_find_with_id(JABBER_PLUGIN_ID);

    PurplePluginProtocolInfo *jabber_protocol_info = PURPLE_PLUGIN_PROTOCOL_INFO(jabber_plugin);

    gboolean force = purple_prefs_get_bool(PREF_PREFIX "/force");

    if (force)
    {
        jabber_protocol_info->send_file = jabber_hfu_xfer_send;
        jabber_protocol_info->new_xfer = jabber_hfu_new_xfer;
    }

    old_blist_node_menu = jabber_protocol_info->blist_node_menu;
    jabber_protocol_info->blist_node_menu = jabber_hfu_blist_node_menu;

    purple_signal_connect(purple_connections_get_handle(), "signed-on", jabber_plugin, PURPLE_CALLBACK(jabber_hfu_signed_on_cb), NULL);

    HFUJabberStreamDataTable = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);

    return TRUE;
}

static PurplePluginPrefFrame *get_plugin_pref_frame(PurplePlugin *plugin)
{
    PurplePluginPrefFrame *frame;
    PurplePluginPref *pref;

    frame = purple_plugin_pref_frame_new();

    pref = purple_plugin_pref_new_with_name_and_label(PREF_PREFIX "/force", _("Force HTTP File Upload"));
    purple_plugin_pref_frame_add(frame, pref);

    return frame;
}


static PurplePluginUiInfo prefs_info = {
    get_plugin_pref_frame,
    0,   /* page_num (Reserved) */
    NULL, /* frame (Reserved) */
    /* Padding */
    NULL,
    NULL,
    NULL,
    NULL
};


static PurplePluginInfo info = {
    PURPLE_PLUGIN_MAGIC,
    PURPLE_MAJOR_VERSION,
    PURPLE_MINOR_VERSION,
    PURPLE_PLUGIN_STANDARD,
    NULL,
    0,
    NULL,
    PURPLE_PRIORITY_DEFAULT,

    "xep-http-file-upload",
    "XMPP HTTP File Upload",
    "0.1.0",

    "Implements XEP-0363: HTTP File Upload",
    "This plugin allows to upload a file to HTTP server",
    "Dmitry Kosenkov <dk-junker@ya.ru>",
    "https://github.com/Junker/purple-xmpp-http-upload",

    plugin_load,
    plugin_unload,
    NULL,

    NULL,
    NULL,
    &prefs_info,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

static void plugin_init(PurplePlugin * plugin)
{
    PurplePluginInfo * info = plugin->info;

    info->dependencies = g_list_prepend(info->dependencies, "prpl-jabber");

    purple_prefs_add_none(PREF_PREFIX);
    purple_prefs_add_bool(PREF_PREFIX "/force", FALSE);

}

PURPLE_INIT_PLUGIN(jabber_http_file_upload, plugin_init, info)
