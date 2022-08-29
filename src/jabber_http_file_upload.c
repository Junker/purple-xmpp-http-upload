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

GHashTable *HFUJabberStreamDataTable;

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

GHashTable *HFUJabberStreamDataTable;
GHashTable *ht_hfu_sending;

#define purple_http_url_get_host(httpurl) (httpurl->host)
#define purple_http_url_get_port(httpurl) (httpurl->port)
#define purple_http_url_get_path(httpurl) (httpurl->path)
static inline void purple_http_url_free(PurpleHttpURL *phl) { g_free(phl->host); g_free(phl->path); g_free(phl->user); g_free(phl->passwd); g_free(phl);  }

#define PREF_PREFIX     "/plugins/xmpp-http-upload"
#define JABBER_PLUGIN_ID "prpl-jabber"


static void jabber_hfu_http_read(gpointer user_data, PurpleSslConnection *ssl_connection, PurpleInputCondition cond)
{
    PurpleXfer *xfer = user_data;
    gchar buf[1024] = {0};

    //Read the server buffer
    size_t rl = purple_ssl_read(ssl_connection, buf, 1024);
    purple_debug_info("jabber_http_upload", "Server file send response was %" G_GSIZE_FORMAT " bytes: %s\n", (gsize) rl, buf);

    if(rl == (size_t)-1)
	return;

    if ((purple_xfer_get_bytes_sent(xfer)) >= purple_xfer_get_size(xfer)) {
	// Looking for HTTP/1.1 201
	if(rl > 12 && g_str_has_prefix(buf, "HTTP/1.") && g_str_has_prefix(buf+8, " 20")) {
	    // 20x statuses are good, should be 201 but who knows those servers
            purple_xfer_set_completed(xfer, TRUE);
	    purple_xfer_end(xfer);
	    return;
	}
    }
    // We've read everything it seems but didn't understand a word
    purple_xfer_cancel_remote(xfer);
    g_return_if_reached();
}

static void jabber_hfu_http_send_connect_cb(gpointer data, PurpleSslConnection *ssl_connection, PurpleInputCondition cond)
{
    PurpleHttpURL *httpurl;
    gchar *headers, *auth = NULL, *expire = NULL, *cookie = NULL;

    PurpleXfer *xfer = data;
    HFUXfer *hfux = purple_xfer_get_protocol_data(xfer);
    HFUJabberStreamData *js_data = hfux->js_data;
    char *filemime = file_get_mime(purple_xfer_get_local_filename(xfer));

    httpurl = purple_http_url_parse(hfux->put_url);

    if (str_equal(js_data->ns, NS_HTTP_FILE_UPLOAD_V0)) {
        char *a = g_hash_table_lookup(hfux->put_headers, "Authorization");
	char *c = g_hash_table_lookup(hfux->put_headers, "Cookie");
        char *e = g_hash_table_lookup(hfux->put_headers, "Expires");
	if(a)
	    auth = g_strdup_printf("Authorisation: %s\r\n", a);
	if(c)
	    cookie = g_strdup_printf("Cookie: %s\r\n", c);
	if(e)
	    expire = g_strdup_printf("Expires: %s\r\n", e);
    }
 
    headers = g_strdup_printf("PUT /%s HTTP/1.0\r\n"
            "Connection: close\r\n"
            "Host: %s\r\n"
            "Content-Length: %" G_GSIZE_FORMAT "\r\n"
            "Content-Type: %s\r\n"
            "User-Agent: libpurple\r\n"
            "%s%s%s\r\n",
	    purple_http_url_get_path(httpurl),
	    purple_http_url_get_host(httpurl),
	    (gsize) purple_xfer_get_size(xfer),
	    (filemime?:"application/octet-stream"),
	    (auth?:""), (expire?:""), (cookie?:""));

    g_free(auth);
    g_free(expire);
    g_free(cookie);
    g_free(filemime);

    hfux->ssl_conn = ssl_connection;
    purple_ssl_input_add(ssl_connection, jabber_hfu_http_read, xfer);

    purple_ssl_write(ssl_connection, headers, strlen(headers));
    g_free(headers);

    purple_xfer_ref(xfer);
    purple_xfer_start(xfer, ssl_connection->fd, NULL, 0);

    purple_xfer_prpl_ready(xfer);
    purple_http_url_free(httpurl);
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
            g_hash_table_insert(hfux->put_headers, g_strdup(xmlnode_get_attrib(header, "name")), xmlnode_get_data(header));
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

    g_debug("Connecting to %s:%d for %s", purple_http_url_get_host(put_httpurl), purple_http_url_get_port(put_httpurl), hfux->put_url);
    purple_ssl_connect(account, purple_http_url_get_host(put_httpurl), purple_http_url_get_port(put_httpurl),
			jabber_hfu_http_send_connect_cb, (PurpleSslErrorFunction)jabber_hfu_http_error_connect_cb, xfer);

    purple_http_url_free(put_httpurl);
}

static void jabber_hfu_xfer_free(PurpleXfer *xfer)
{
    HFUXfer *hfux = purple_xfer_get_protocol_data(xfer);

    g_return_if_fail(hfux != NULL);

    g_free(hfux->put_url);
    g_free(hfux->get_url);

    if(hfux->put_headers)
        g_hash_table_destroy(hfux->put_headers);

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
    filesize = g_strdup_printf("%" G_GSIZE_FORMAT, (gsize) purple_xfer_get_size(xfer));
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

static void
jabber_hfu_xmlnode_send_cb(PurpleConnection *gc, xmlnode **packet, gpointer null)
{

  if (*packet != NULL && (*packet)->name) {
    if (g_strcmp0 ((*packet)->name, "message") == 0) {
      xmlnode *node_body = xmlnode_get_child (*packet, "body");
      if (node_body) {
	char *url = xmlnode_get_data(node_body);
        HFUXfer *hfux = g_hash_table_lookup(ht_hfu_sending, url);
	g_free(url);
        if(hfux) {
           xmlnode *x, *url;
           x = xmlnode_new_child (*packet, "x");
           xmlnode_set_namespace (x, NS_OOB_X_DATA);
           g_debug ("Adding OOB Data to URL: %s", hfux->get_url);
           url = xmlnode_new_child(x, "url");
	   xmlnode_insert_data(url, hfux->get_url, -1);
        }
      }
    }
  }
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
           // Send raw URL to handle it later
           g_hash_table_insert(ht_hfu_sending, hfux->get_url, hfux);
           purple_conv_im_send_with_flags(conv_im, hfux->get_url, PURPLE_MESSAGE_RAW);
	   g_hash_table_remove(ht_hfu_sending, hfux->get_url);
        }
    }
}

static void jabber_hfu_xfer_end(PurpleXfer *xfer)
{
    g_debug("This is the end.");
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
        if ((errno != EAGAIN) && (errno != EINTR))
            return -1;

        return 0;
    } else if ((purple_xfer_get_bytes_sent(xfer)+tlen) >= purple_xfer_get_size(xfer))
		xfer->status = PURPLE_XFER_STATUS_DONE; // sneaky cheat

    return tlen;
}

static void jabber_hfu_xfer_ack(PurpleXfer *xfer, const guchar *buffer, size_t len)
{
    if (purple_xfer_is_completed(xfer))
	xfer->status = PURPLE_XFER_STATUS_STARTED; // hideous uncheat
}

static void jabber_hfu_xfer_init(PurpleXfer *xfer)
{
    HFUXfer *hfux = purple_xfer_get_protocol_data(xfer);
    JabberStream *js = hfux->js;
    HFUJabberStreamData *js_data = g_hash_table_lookup(HFUJabberStreamDataTable, js);

    hfux->js_data = js_data;

    purple_debug_info("jabber_http_upload", "in jabber_hfu_xfer_init\n");
    if (!js_data->ns)
    {
        purple_notify_error(hfux->js->gc, _("File Send Failed"), _("File Send Failed"), _("HTTP File Upload is not supported by server"));

        purple_debug_info("jabber_http_upload", "HTTP File Upload is not supported by server\n");
        purple_xfer_cancel_local(xfer);

        return;
    }

    if (js_data->max_file_size && purple_xfer_get_size(xfer) > js_data->max_file_size)
    {
        gchar *msg = g_strdup_printf(_("HTTP File Upload maximum file size is %" G_GSIZE_FORMAT " bytes"), js_data->max_file_size);
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
    purple_xfer_set_write_fnc(xfer, jabber_hfu_xfer_write);
    purple_xfer_set_ack_fnc(xfer, jabber_hfu_xfer_ack);
    purple_xfer_set_end_fnc(xfer, jabber_hfu_xfer_end);

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

static void jabber_hfu_signed_off_cb(PurpleConnection *conn, void *data)
{
    PurpleAccount *account = purple_connection_get_account(conn);

    if (strcmp(JABBER_PLUGIN_ID, purple_account_get_protocol_id(account)))
        return;

    JabberStream *js = purple_connection_get_protocol_data(conn);

    HFUJabberStreamData *js_data = g_hash_table_lookup(HFUJabberStreamDataTable, js);

    if(js_data) {
	g_hash_table_remove(HFUJabberStreamDataTable, js);
	g_free(js_data->host);
	g_free(js_data);
    }
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
    PurplePlugin *jabber_plugin = purple_plugins_find_with_id(JABBER_PLUGIN_ID);

    PurplePluginProtocolInfo *jabber_protocol_info = PURPLE_PLUGIN_PROTOCOL_INFO(jabber_plugin);
    jabber_protocol_info->blist_node_menu = old_blist_node_menu;

    purple_signals_disconnect_by_handle(plugin);
    g_hash_table_destroy(ht_hfu_sending);
    g_hash_table_destroy(HFUJabberStreamDataTable);
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

    purple_signal_connect(purple_connections_get_handle(), "signed-on", plugin, PURPLE_CALLBACK(jabber_hfu_signed_on_cb), NULL);
    purple_signal_connect(purple_connections_get_handle(), "signed-off", plugin, PURPLE_CALLBACK(jabber_hfu_signed_off_cb), NULL);

    HFUJabberStreamDataTable = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);
    ht_hfu_sending = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, NULL);
    purple_signal_connect(jabber_plugin, "jabber-sending-xmlnode", plugin, PURPLE_CALLBACK(jabber_hfu_xmlnode_send_cb), NULL);

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
