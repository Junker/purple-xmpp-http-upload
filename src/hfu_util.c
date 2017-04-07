#include <gio/gio.h>

gchar* file_get_mime(const gchar *filename)
{
    gboolean is_certain = FALSE;

    char *content_type = g_content_type_guess(filename, NULL, 0, &is_certain);

    if (content_type != NULL)
    {
        gchar *mime_type = g_content_type_get_mime_type(content_type);

        g_free(content_type);

        return mime_type;
    }

    return NULL;
}