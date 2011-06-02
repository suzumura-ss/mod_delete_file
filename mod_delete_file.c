/* 
 * Copyright 2011 Toshiyuki Terashita
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include "httpd.h"
#include "http_log.h"
#include "http_config.h"
#include "http_protocol.h"
#include "ap_config.h"
#include "apr_strings.h"
#include "apr_file_info.h"

#define AP_LOG_DEBUG(rec, fmt, ...) ap_log_rerror(APLOG_MARK, APLOG_DEBUG,  0, rec, fmt, ##__VA_ARGS__)
#define AP_LOG_INFO(rec, fmt, ...)  ap_log_rerror(APLOG_MARK, APLOG_INFO,   0, rec, "[" __FILE__ "] " fmt, ##__VA_ARGS__)
#define AP_LOG_WARN(rec, fmt, ...)  ap_log_rerror(APLOG_MARK, APLOG_WARNING,0, rec, "[" __FILE__ "] " fmt, ##__VA_ARGS__)
#define AP_LOG_ERR(rec, fmt, ...)   ap_log_rerror(APLOG_MARK, APLOG_ERR,    0, rec, "[" __FILE__ "] " fmt, ##__VA_ARGS__)

/* text/json handler */
static int delete_handler(request_rec *r)
{
  int result;

  if(strcmp(r->handler, "delete_file")) {
    return DECLINED;
  }
  if(r->method_number!=M_DELETE) {
    return DECLINED;
  }
  
  result = apr_file_remove(r->filename, r->pool);

  if(result==APR_SUCCESS) {
    ap_set_content_type(r, "text/plain");
    ap_rprintf(r, "Deleted.\r\n");
    result = OK;
  } else {
    char buf[1024];
    AP_LOG_INFO(r, "apr_file_remove(%s) => %s(%d)", r->filename, apr_strerror(result, buf, 1024), result);
    switch(result) {
    case APR_ENOENT:
      result = HTTP_NOT_FOUND;    // 404
      break;
    case APR_EACCES:
      result = HTTP_FORBIDDEN;    // 403
      break;
    default:
      result = HTTP_BAD_REQUEST;  // 400
    }
  }
  return result;
}

static void delete_file_register_hooks(apr_pool_t *p)
{
  ap_hook_handler(delete_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA delete_file_module = {
  STANDARD20_MODULE_STUFF, 
  NULL,                       /* create per-dir    config structures */
  NULL,                       /* merge  per-dir    config structures */
  NULL,                       /* create per-server config structures */
  NULL,                       /* merge  per-server config structures */
  NULL,                       /* table of config file commands       */
  delete_file_register_hooks  /* register hooks                      */
};

