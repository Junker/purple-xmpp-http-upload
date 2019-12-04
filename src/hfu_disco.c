
#include <stdio.h>
#include <string.h>

#include "debug.h"

#include "disco.h"
#include "iq.h"

#include "hfu_disco.h"
#include "hfu_util.h"
#include "jabber_http_file_upload.h"


static void jabber_hfu_disco_info_cb(JabberStream *js, const char *from,
                                 JabberIqType type, const char *id,
                                 xmlnode *packet, gpointer data)
{
	xmlnode *query, 
		*feature = NULL, 
		*field = NULL,
		*value = NULL,
		*x = NULL;

	HFUJabberStreamData *js_data = NULL;

	query = xmlnode_get_child_with_namespace(packet, "query", NS_DISCO_INFO);

	if (type != JABBER_IQ_RESULT || query == NULL) 
		return;

	js_data = g_hash_table_lookup(HFUJabberStreamDataTable, js);
	// Always prefer latest standard, skip if already found
	if (!js_data || str_equal(js_data->ns, NS_HTTP_FILE_UPLOAD_V0))
		return;

        for (feature = xmlnode_get_child(query, "feature") ; feature; feature = xmlnode_get_next_twin(feature)) 
        {
		const char *var = xmlnode_get_attrib(feature, "var");
		if(!var)
			continue;

		if(str_equal(var, NS_HTTP_FILE_UPLOAD) && js_data->ns == NULL)
			js_data->ns = NS_HTTP_FILE_UPLOAD;
		else if(str_equal(var, NS_HTTP_FILE_UPLOAD_V0))
			js_data->ns = NS_HTTP_FILE_UPLOAD_V0;
		else
			continue;

		g_free(js_data->host);
		js_data->host = g_strdup(from);

		x = xmlnode_get_child_with_namespace(query, "x", "jabber:x:data");
		if (x)
		{
			for(field = xmlnode_get_child(x, "field"); field; field = xmlnode_get_next_twin(field)) 
			{
				const char *var = xmlnode_get_attrib(field, "var");

				if(var && str_equal(var, "max-file-size")) 
					if((value = xmlnode_get_child(field, "value"))) 
						js_data->max_file_size = (gsize) atol(xmlnode_get_data(value));
			}
		}
	}
}

static void jabber_hfu_disco_server_items_result_cb(JabberStream *js, const char *from,
                                    JabberIqType type, const char *id,
                                    xmlnode *packet, gpointer data)
{

	xmlnode *query, *child;


	if (!from || strcmp(from, js->user->domain) != 0)
		return;

	if (type == JABBER_IQ_ERROR)
		return;

	query = xmlnode_get_child(packet, "query");

	for(child = xmlnode_get_child(query, "item"); child; child = xmlnode_get_next_twin(child)) 
	{
		JabberIq *iq;
		const char *jid;

		if(!(jid = xmlnode_get_attrib(child, "jid")))
			continue;

		if(xmlnode_get_attrib(child, "node") != NULL)
			continue;

		iq = jabber_iq_new_query(js, JABBER_IQ_GET, NS_DISCO_INFO);
		xmlnode_set_attrib(iq->node, "to", jid);
		jabber_iq_set_callback(iq, jabber_hfu_disco_info_cb, NULL);
		jabber_iq_send(iq);
	}
}

void jabber_hfu_disco_items_server(JabberStream *js)
{
	JabberIq *iq = jabber_iq_new_query(js, JABBER_IQ_GET, NS_DISCO_ITEMS);

	xmlnode_set_attrib(iq->node, "to", js->user->domain);

	jabber_iq_set_callback(iq, jabber_hfu_disco_server_items_result_cb, NULL);
	jabber_iq_send(iq);
}



