#include "jabber.h"

typedef struct _HFUJabberStreamData {
    gchar *host;
    gsize max_file_size;
    gchar *ns;
} HFUJabberStreamData;


typedef struct _HFUXfer {
    JabberStream *js;
    HFUJabberStreamData *js_data;
    PurpleSslConnection *ssl_conn;
    gchar *put_url;
    gchar *get_url;
    GHashTable *put_headers;
} HFUXfer;

extern GHashTable *HFUJabberStreamDataTable;

#define NS_HTTP_FILE_UPLOAD "urn:xmpp:http:upload"
#define NS_HTTP_FILE_UPLOAD_V0 "urn:xmpp:http:upload:0"

#define purple_xfer_get_protocol_data(xfer) ((xfer)->data)
#define purple_xfer_set_protocol_data(xfer, proto_data) ((xfer)->data = (proto_data))
