/*
   +----------------------------------------------------------------------+
   | PHP version 4.0                                                      |
   +----------------------------------------------------------------------+
   | Copyright (c) 1997, 1998, 1999, 2000 The PHP Group                   |
   +----------------------------------------------------------------------+
   | This source file is subject to version 2.02 of the PHP license,      |
   | that is bundled with this package in the file LICENSE, and is        |
   | available at through the world-wide-web at                           |
   | http://www.php.net/license/2_02.txt.                                 |
   | If you did not receive a copy of the PHP license and are unable to   |
   | obtain it through the world-wide-web, please send a note to          |
   | license@php.net so we can mail you a copy immediately.               |
   +----------------------------------------------------------------------+
   | Authors: Brendan W. McAdams <brendan@plexmedia.com>                  |
   |              Doug DeJulio <ddj@redhat.com>                           |
   +----------------------------------------------------------------------+
*/ 

	#include <cv_api.h>
	
	extern zend_module_entry ccvs_module_entry;
	
	#define ccvs_module_ptr &ccvs_module_entry
	#define phpext_ccvs_ptr ccvs_module_ptr
	
	/* Declare functions not in cv_api.h but in libccvs.a. */
	char *hks_ptr_ptrtostring(void *vptr);
	void *hks_ptr_stringtoptr(char *str);
	
	/* Declare the Functions this Module Makes Available to Zend */
	
	
		/* Pre-declarations of functions */
		ZEND_FUNCTION(ccvs_init);
		ZEND_FUNCTION(ccvs_done);
		ZEND_FUNCTION(ccvs_new);
		ZEND_FUNCTION(ccvs_add);
		ZEND_FUNCTION(ccvs_delete);
		ZEND_FUNCTION(ccvs_auth);
		ZEND_FUNCTION(ccvs_return);
		ZEND_FUNCTION(ccvs_reverse);
		ZEND_FUNCTION(ccvs_sale);
		ZEND_FUNCTION(ccvs_void);
		ZEND_FUNCTION(ccvs_status);
		ZEND_FUNCTION(ccvs_count);
		ZEND_FUNCTION(ccvs_lookup);
		ZEND_FUNCTION(ccvs_report);
		ZEND_FUNCTION(ccvs_command);
		ZEND_FUNCTION(ccvs_textvalue); 
		PHP_MINFO_FUNCTION(ccvs);
		
		/* Declare the information we need to dynamically link this module later */
		#if COMPILE_DL
		DLEXPORT zend_module_entry *get_module(void) { return &ccvs_module_entry; }
		#endif
		
	/* End exports */
	
