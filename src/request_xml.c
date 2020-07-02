/**
 * Nginx CDN module
 *
 * @author: Assen Totin assen.totin@gmail.com
 */

#include "common.h"
#include "utils.h"

#define XML_ENCODING "ISO-8859-1"

/**
 * Handle XML error
 */
static ngx_int_t error_xml(ngx_http_request_t *r, xmlTextWriterPtr writer, xmlBufferPtr buf, char *element) {
	xmlErrorPtr err;

	err = xmlGetLastError();
	ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "XML writer error at %s: %s", element, err->message);
	xmlFreeTextWriter(writer);
	xmlBufferFree(buf);
	return NGX_HTTP_INTERNAL_SERVER_ERROR;
}


/**
 * Prepare XML request GET
 */
ngx_int_t request_get_xml(session_t *session, metadata_t *metadata, ngx_http_request_t *r) {
	int i, ret;
	xmlTextWriterPtr writer;
	xmlBufferPtr buf;

	// Init XML buffer
	if ((buf = xmlBufferCreate()) == NULL) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to create XML buffer");
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	// Init XML writer
	if ((writer = xmlNewTextWriterMemory(buf, 0)) == NULL) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to create XML writer");
		xmlBufferFree(buf);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	// Start document
	if ((ret = xmlTextWriterStartDocument(writer, NULL, XML_ENCODING, NULL)) < 0)
		return error_xml(r, writer, buf, "xmlTextWriterStartDocument");

	// Root element
	if ((ret = xmlTextWriterStartElement(writer, BAD_CAST "request")) < 0)
		return error_xml(r, writer, buf, "request");

	// File ID
	if ((ret = xmlTextWriterWriteElement(writer, BAD_CAST "file_id", (const xmlChar *) metadata->file)) < 0)
		return error_xml(r, writer, buf, "file_id");

	// HTTP method
	if ((ret = xmlTextWriterWriteElement(writer, BAD_CAST "http_method", (const xmlChar *) session->http_method)) < 0)
		return error_xml(r, writer, buf, "http_method");

	// Add the authorisation value if extracted
	if (session->auth_value) {
		if ((ret = xmlTextWriterWriteElement(writer, BAD_CAST "auth_value", (const xmlChar *) session->auth_value)) < 0)
			return error_xml(r, writer, buf, "auth_value");
	}

	// Headers: make an array of objects with name and value
	if (! strcmp(session->all_headers, "yes")) {
		if ((ret = xmlTextWriterStartElement(writer, BAD_CAST "headers")) < 0)
			return error_xml(r, writer, buf, "headers");

		for (i=0; i < session->headers_count; i++) {
			if ((ret = xmlTextWriterStartElement(writer, BAD_CAST "header")) < 0)
				return error_xml(r, writer, buf, "header");
			if ((ret = xmlTextWriterWriteElement(writer, BAD_CAST "name", (const xmlChar *) session->headers[i].name)) < 0)
				return error_xml(r, writer, buf, "name");
			if ((ret = xmlTextWriterWriteElement(writer, BAD_CAST "value", (const xmlChar *) session->headers[i].value)) < 0)
				return error_xml(r, writer, buf, "value");
			if ((ret = xmlTextWriterEndElement(writer)) < 0)
				return error_xml(r, writer, buf, "xmlTextWriterEndElement");
		}

		if ((ret = xmlTextWriterEndElement(writer)) < 0)
			return error_xml(r, writer, buf, "xmlTextWriterEndElement");
	}

	// Cookies: make an array of objects with name and value
	if (! strcmp(session->all_cookies, "yes")) {
		if ((ret = xmlTextWriterStartElement(writer, BAD_CAST "cookies")) < 0)
			return error_xml(r, writer, buf, "cookies");

		for (i=0; i < session->cookies_count; i++) {
			if ((ret = xmlTextWriterStartElement(writer, BAD_CAST "cookie")) < 0)
				return error_xml(r, writer, buf, "cookie");
			if ((ret = xmlTextWriterWriteElement(writer, BAD_CAST "name", (const xmlChar *) session->cookies[i].name)) < 0)
				return error_xml(r, writer, buf, "name");
			if ((ret = xmlTextWriterWriteElement(writer, BAD_CAST "value", (const xmlChar *) session->cookies[i].value)) < 0)
				return error_xml(r, writer, buf, "value");
			if ((ret = xmlTextWriterEndElement(writer)) < 0)
				return error_xml(r, writer, buf, "xmlTextWriterEndElement");
		}

		if ((ret = xmlTextWriterEndElement(writer)) < 0)
			return error_xml(r, writer, buf, "xmlTextWriterEndElement");
	}

	// Close root element
	if ((ret = xmlTextWriterEndElement(writer)) < 0)
		return error_xml(r, writer, buf, "xmlTextWriterEndElement");

	if ((session->auth_request = ngx_pcalloc(r->pool, strlen((const char *) buf->content) + 1)) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for XML auth request.", strlen((const char *) buf->content) + 1);
		return NGX_ERROR;
	}
	strcpy(session->auth_request, (const char *) buf->content);

	xmlFreeTextWriter(writer);
	xmlBufferFree(buf);

	return NGX_OK;
}

/**
 * Prepare XML request POST
 */
ngx_int_t request_post_xml(session_t *session, metadata_t *metadata, ngx_http_request_t *r) {
	int ret;
	char *s1, *s2;
	xmlTextWriterPtr writer;
	xmlBufferPtr buf;

	// Prepare chars for int values
	if ((s1 = ngx_pcalloc(r->pool, 24)) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for XML int conversion.", 24);
		return NGX_ERROR;
	}
	if ((s2 = ngx_pcalloc(r->pool, 24)) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for XML int conversion.", 24);
		return NGX_ERROR;
	}

	// Init XML buffer
	if ((buf = xmlBufferCreate()) == NULL) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to create XML buffer");
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	// Init XML writer
	if ((writer = xmlNewTextWriterMemory(buf, 0)) == NULL) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to create XML writer");
		xmlBufferFree(buf);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	// Start document
	if ((ret = xmlTextWriterStartDocument(writer, NULL, XML_ENCODING, NULL)) < 0)
		return error_xml(r, writer, buf, "xmlTextWriterStartDocument");

	// Root element
	if ((ret = xmlTextWriterStartElement(writer, BAD_CAST "request")) < 0)
		return error_xml(r, writer, buf, "request");

	// File ID
	if ((ret = xmlTextWriterWriteElement(writer, BAD_CAST "file_id", (const xmlChar *) metadata->file)) < 0)
		return error_xml(r, writer, buf, "file_id");

	// HTTP method
	if ((ret = xmlTextWriterWriteElement(writer, BAD_CAST "http_method", (const xmlChar *) session->http_method)) < 0)
		return error_xml(r, writer, buf, "http_method");

	// Add authorisation value
	if (session->auth_value) {
		if ((ret = xmlTextWriterWriteElement(writer, BAD_CAST "auth_value", (const xmlChar *) session->auth_value)) < 0)
			return error_xml(r, writer, buf, "auth_value");
	}

	// Add filename
	if ((ret = xmlTextWriterWriteElement(writer, BAD_CAST "filename", (const xmlChar *) metadata->filename)) < 0)
		return error_xml(r, writer, buf, "filename");

	// Add length
	sprintf(s1, "%li", metadata->length);
	if ((ret = xmlTextWriterWriteElement(writer, BAD_CAST "length", (const xmlChar *) s1)) < 0)
		return error_xml(r, writer, buf, "length");

	// Add content_type
	if ((ret = xmlTextWriterWriteElement(writer, BAD_CAST "content_type", (const xmlChar *) metadata->content_type)) < 0)
		return error_xml(r, writer, buf, "content_type");

	// Add content_disposition
	if ((ret = xmlTextWriterWriteElement(writer, BAD_CAST "content_disposition", (const xmlChar *) metadata->content_disposition)) < 0)
		return error_xml(r, writer, buf, "content_disposition");

	// Add upload_date
	sprintf(s2, "%li", metadata->upload_date);
	if ((ret = xmlTextWriterWriteElement(writer, BAD_CAST "upload_date", (const xmlChar *) s2)) < 0)
		return error_xml(r, writer, buf, "upload_date");

	// Add etag
	if ((ret = xmlTextWriterWriteElement(writer, BAD_CAST "etag", (const xmlChar *) metadata->etag)) < 0)
		return error_xml(r, writer, buf, "etag");

	// Close root element
	if ((ret = xmlTextWriterEndElement(writer)) < 0)
		return error_xml(r, writer, buf, "xmlTextWriterEndElement");

	xmlFreeTextWriter(writer);

	session->auth_request = ngx_pcalloc(r->pool, strlen((const char *) buf->content) + 1);
	if (session->auth_request == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for XML auth request.", strlen((const char *) buf->content) + 1);
		return NGX_ERROR;
	}
	strcpy(session->auth_request, (const char *) buf->content);

	xmlBufferFree(buf);

	return NGX_OK;
}


/**
 * Process XML response GET
 */
ngx_int_t response_get_xml(session_t *session, metadata_t *metadata, ngx_http_request_t *r) {
	xmlDoc *doc = NULL;
	xmlNode *root_element = NULL, *cur_node = NULL;
	ngx_int_t ret;

	// If we got no repsonse, skip processing
	if (! session->auth_response) {
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "No authorisation response received, skipping XML processing");
		return NGX_OK;
	}

	if ((doc = xmlReadMemory(session->auth_response, strlen(session->auth_response), "noname.xml", XML_ENCODING, 0)) == NULL) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to parse XML: %s", session->auth_response);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	// Get the root element node
	root_element = xmlDocGetRootElement(doc);

	// Walk around the XML which we received from the authentication servier, session->auth_response
	for (cur_node = root_element->children; cur_node; cur_node = cur_node->next) {
		if ((cur_node->type == XML_ELEMENT_NODE) && (cur_node->children)) {
			if (! xmlStrcmp(cur_node->name, (const xmlChar *)"filename")) {
				if ((ret = set_metadata_field(r, &metadata->filename, "filename", (const char *) cur_node->children->content)) > 0)
					return ret;
			}

			else if (! xmlStrcmp(cur_node->name, (const xmlChar *)"error")) {
				if ((ret = set_metadata_field(r, &metadata->filename, "error", (const char *) cur_node->children->content)) > 0)
					return ret;
			}

			else if (! xmlStrcmp(cur_node->name, (const xmlChar *)"auth_value")) {
				if ((ret = set_metadata_field(r, &metadata->auth_value, "auth_value", (const char *) cur_node->children->content)) > 0)
					return ret;
			}

			else if (! xmlStrcmp(cur_node->name, (const xmlChar *)"content_type")) {
				if ((ret = set_metadata_field(r, &metadata->content_type, "content_type", (const char *) cur_node->children->content)) > 0)
					return ret;
			}

			else if (! xmlStrcmp(cur_node->name, (const xmlChar *)"content_disposition")) {
				if ((ret = set_metadata_field(r, &metadata->content_disposition, "content_disposition", (const char *) cur_node->children->content)) > 0)
					return ret;
			}

			else if (! xmlStrcmp(cur_node->name, (const xmlChar *)"etag")) {
				if ((ret = set_metadata_field(r, &metadata->etag, "etag", (const char *) cur_node->children->content)) > 0)
					return ret;
			}

			else if (! xmlStrcmp(cur_node->name, (const xmlChar *)"status")) {
				metadata->status = atoi((const char *) cur_node->children->content);
				ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found metadata status: %l", metadata->status);
			}

			else if (! xmlStrcmp(cur_node->name, (const xmlChar *)"length")) {
				metadata->length = atoi((const char *) cur_node->children->content);
				ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found metadata length: %l", metadata->length);
			}

			else if (! xmlStrcmp(cur_node->name, (const xmlChar *)"upload_date")) {
				metadata->upload_date = atoi((const char *) cur_node->children->content);
				ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found metadata upload_date: %l", metadata->upload_date);
			}
		}
	}

	// Cleanup
	xmlFreeDoc(doc);
	xmlCleanupParser();

	return NGX_OK;
}

/**
 * Process XML response POST
 */
ngx_int_t response_post_xml(session_t *session, metadata_t *metadata, ngx_http_request_t *r) {
	xmlDoc *doc = NULL;
	xmlNode *root_element = NULL, *cur_node = NULL;

	// If we got no repsonse, skip processing
	if (! session->auth_response) {
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "No authorisation response received, skipping XML processing");
		return NGX_OK;
	}

	if ((doc = xmlReadMemory(session->auth_response, strlen(session->auth_response), "noname.xml", XML_ENCODING, 0)) == NULL) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to parse XML: %s", session->auth_response);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	// Get the root element node
	root_element = xmlDocGetRootElement(doc);

	// Walk around the XML which we received from the authentication servier, session->auth_response
	for (cur_node = root_element->children; cur_node; cur_node = cur_node->next) {
		if ((cur_node->type == XML_ELEMENT_NODE) && (cur_node->children)) {
			if (! xmlStrcmp(cur_node->name, (const xmlChar *)"status")) {
				metadata->status = atoi((const char *) cur_node->children->content);
				ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found metadata status: %l", metadata->status);
			}
		}
	}

	// Cleanup
	xmlFreeDoc(doc);
	xmlCleanupParser();

	return NGX_OK;
}

