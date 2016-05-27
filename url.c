/*
	Implements a few useful function to manipulate URLs.
	They have been written to achieved URL canonicalization, as defined in 
	https://developers.google.com/safe-browsing/developers_guide_v3#Canonicalization
 */



#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>


// Convert an hexadecimal character [0-9a-zA-Z] to it's integer value
#define VAL(x) ((x>='0' && x<='9') ? x-'0' : ((x>='a' && x<='f') ? x-'a'+10 : ((x>='A' && x<='F') ? x-'A'+10 : 0)))

#define LOWERCASE(x) ((x)>='A' && (x)<='Z' ? (x)-'A'+'a' : (x))

// Convert a "%AB" or "%ab" hexadecimal string to its integer value, or return -1 if was not an hex string
static inline int url_DecodePercent(const char *s) {
	if(	*s == '%'
	  	&& 	((*(s+1)>='0' &&  *(s+1)<='9') || (*(s+1)>='A' &&  *(s+1)<='F') || (*(s+1)>='a' &&  *(s+1)<='f'))
	  	&& 	((*(s+2)>='0' &&  *(s+2)<='9') || (*(s+2)>='A' &&  *(s+2)<='F') || (*(s+2)>='a' &&  *(s+2)<='f')) )
		return(16*VAL(*(s+1)) + VAL(*(s+2)));	
	else
		return(-1);
}


static char *url_RFC3986_ReservedChars = "!*'();:@&=+$,/?#[]";

/**
 * Check is a given char is one of the RFC 3986 reserved characters,
 * that is one of the following : "!*'();:@&=+$,/?#[]".	
 * @param  c Character to be checked.
 * @return   True if the given character is reserved, false otherwise.
 */
static inline bool url_IsReserved(const char c)
{
	char *ptr = url_RFC3986_ReservedChars;
	while(*ptr)
		if(*ptr==c)
			return(true);
		else 
			ptr++;
	return(false);
}



/**
 * Remove leading and trailing spaces, as well as tab (0x09), CR (0x0d), 
 * and LF (0x0a) characters from the URL. Returns cleaned URL in a newly 
 * allocated string.
 * @param  string  Pointer to string to be cleaned.
 * @param  len     Length of string. If 0, then strlen() will be called.
 * @param  new_len If not NULL, pointer to a long where the length of the
 *                 new string will be stored.
 * @return         Pointer to a newly allocated string, must be freed using
 *                 free(), or NULL in case of error.
 */
extern char *url_RemoveTabCRLF(const char *string, long len, long *new_len)
{
	// printf("url_RemoveTabCRLF() [%s]\n", string);
	if(len==0)
		len=strlen(string);

	const char *end_of_string = string + len - 1;

	char *clean = malloc(len + 1);
	if(clean == NULL)
		return(NULL);
	char *begin_clean = clean;

	// Remove leading spaces
	while(*string && *string==' ') 
		string++;

	// Remove trailing spaces
	while(end_of_string-string>=0 && *end_of_string==' ')
		end_of_string--;

	while(end_of_string-string>=0) {
		switch(*string) {
			case '\r':
			case '\n':
			case '\t':
				break;
			default:
				*(clean++) = *string;
				// printf("url_RemoveTabCRLF() char copied = [%c]\n", *string);
				break;
		}
		string++;
	}
	*clean = '\0';

	if(new_len)
		*new_len = clean - begin_clean;

	return(begin_clean);
}


/**
 * Remove the fragment part of an URL. For example, shorten 'http://google.com/#frag' 
 * to 'http://google.com/'. The initial string is changed by putting a NUL character
 * where the first '#' is found.
 * @param  string  Pointer to string holding the fragment.
 * @param  new_len If not NULL, pointer to a long where the length of the modified
 *                 string will be stored.
 * @return         Pointer to the fragment string, or NULL.
 */
extern char *url_RemoveFragment(char *string, long *new_len)
{
	char *p = string;
	for( ; *p && *p!='#'; p++)
		;
	if(new_len)
		*new_len = p - string;
	if(*p == '#') {
		*p = '\0';
		return(p+1);
	} else 
		return(NULL);
}


/**
 * Remove the query part of an URL (part starting with ?). The initial
 * string is changed by putting a NUL character where the first '?' is found.
 * @param  string  Pointer to a string holding the URL.
 * @param  new_len Pointer to long. If not NULL, will be loaded with
 *                 the new length of the shortened URL.
 * @return         Pointer to query part if found, or NULL.
 */
extern char *url_RemoveQuery(char *string, long *new_len)
{
	char *p = string;
	for( ; *p && *p!='?'; p++)
		;
	if(new_len)
		*new_len = p - string;
	if(*p == '?') {
		*p = '\0';
		return(p+1);
	} else 
		return(NULL);
}


/**
 * Percent-decode a string, calling itself until all percend-decoding is done.
 * Returned string is stored in a newly allocated buffer that needs to be freed.
 * @param  string  Pointer to string to be decoded.
 * @param  len     Length of string or 0. If len is 0, strlen() will be called.
 * @param  new_len Pointer to a long where to store length of the decoded string.
 *                 Can be NULL if you don't need the length of the returned string.
 * @return         Pointer to a newly allocated decoded string. Needs to be freed
 *                 with free(). NULL if error.
 */
extern inline char *url_Unescape(const char *string, long len, long *new_len)
{

	// printf("Unescape() begin [%s] [%ld] [%ld]\n", string, len, (new_len ? *new_len : -1));

	if(len==0)
		len=strlen(string);

	char *decoded_string = malloc(strlen(string)+1);
	if(decoded_string==NULL) 
		return(NULL);
	char *begin_decoded = decoded_string;

	for(; *string; string++, decoded_string++) { 
		if(*string == '%') { 
			int code = url_DecodePercent(string);
			if(code != -1) {
				*decoded_string = code; 
				string +=2; 
			} else 
				*decoded_string = *string;
		} else
			*decoded_string = *string; 
	}
	*decoded_string = '\0';	

	long decoded_string_length = decoded_string - begin_decoded;
	if(decoded_string_length == len) {
		// No more unescape() needed
		if(new_len)
			*new_len = decoded_string - begin_decoded;
		return(begin_decoded);
	} else {
		// Recursevely call Unescape()
		char *next_string = url_Unescape(begin_decoded, decoded_string_length, new_len);
		free(begin_decoded);
		return(next_string);
	}

}


/**
 * Normalize an URL. The URL will be cleaned with url_RemoveTabCRLF(), then its 
 * fragment will be removed with url_RemoveFragment(). The URL will be unescaped
 * with url_Unescape() before being normalizes. Return a normalized URL in a 
 * newly allocated block of memory or NULL if error. WARNING : current limitation is 
 * that we don't do any normalization if the hostname is replaced by an IP address.
 * @param  src     Pointer to string holding the URL to be normalized.
 * @param  len     Length of source string. If 0, strlen() will be called.
 * @param  new_len If not NULL, pointer to a long where the length of the new string will be stored.
 * @return         Pointer to a newly allocated string. Must freed using free(). Or
 *                 NULL of error.
 */
extern char *url_Normalize(const char *src, const long len, long *new_len)
{
	long tmp;

	if(new_len == NULL)
		new_len = &tmp;

	// printf("url_Normalize() [%s]\n", src);

	char *str1 = url_RemoveTabCRLF(src, len, new_len);
	// printf("%-16s = [%s]\n", "CLEANED", str1);
	// printf("new_len = %ld\n", *new_len);
	url_RemoveFragment(str1, new_len);
	// printf("%-16s = [%s]\n", "FRAGMENT REMOVED", str1);
	// printf("new_len = %ld\n", *new_len);	
	char *str2 = url_Unescape(str1, *new_len, new_len);
	// printf("%-16s = [%s]\n", "UNESCAPED", str2);
	// printf("new_len = %ld\n", *new_len);		

	// Save begining of source string
	char *begin_source = str2;

	// Destination string cannot be longer that the initial string + "http://" + trailing '/'
	char *dest = malloc(*new_len+1+8);
	if(dest==NULL)
		return(NULL);

	// Save the beginning of the destination string
	char *begin_dest = dest;

	// Copy the scheme part
	for( ; *str2 && *str2!=':'; dest++, str2++)
		*dest = LOWERCASE(*str2);

	if(*str2=='\0') {
		// There is no scheme part, use "http" as default
		str2 = begin_source;
		dest = begin_dest;
		strcpy(dest, "http://");
		dest +=7;	
	} else if( *(str2)==':' && *(str2+1)=='/' && *(str2+2)=='/') {
		// Copy the "://" part
		*(dest++) = *(str2++); *(dest++) = *(str2++); *(dest++) = *(str2++);
	} else
		goto bad;

	// Find the next '/' so we can have the beginning and the end of the host name
	char *begin_hostname = str2;
	while(*str2 && *str2!='/')
		str2++;
	str2--;
	char *end_hostname = str2;

	// Ignore leading dots
	while(*begin_hostname && *begin_hostname=='.')
		begin_hostname++;

	// Ignore trailing dots
	while(end_hostname-begin_hostname>0 && *end_hostname=='.')
		end_hostname--;

	// We should normalize the IP addresse, but we expect the IP address to be a 4 dot-separated decimal values
	
	// Copy the host name, making sure all characters are lowercase
	for( ; end_hostname-begin_hostname>=0; dest++, begin_hostname++)
		*dest = LOWERCASE(*begin_hostname);

	str2++;
	*(dest++)='/';

	if(*str2!='/') {
		*dest = '\0';
		goto good;
	}

	char *after_hostname = dest;

	bool in_query = false;
	while(*str2) {
		if(in_query) {
			// If in query, just copy the character
			*(dest++) = *(str2++);
		} else {
			// We are in the path
			switch(*str2) {
				case '?':
					// Entering query
					*(dest++) = *(str2++);
					in_query = true;
					break;
				case '/':
					if(*(str2+1)=='.' && *(str2+2)=='/') {
						// replace "/./" with "/"
						*(dest++) = '/';
						str2 +=3;
					} else if(*(str2+1)=='.' && *(str2+2)=='.' && (*(str2+3)=='/' || *(str2+3)=='\0')) {
						// Remove "/../" along with the preceding path component.
						if(*(str2+3)=='\0')
							str2 +=3;
						else str2 +=4;
						do {
							dest--;
						} while(dest-after_hostname>=0 && *dest!='/');
						dest++;
					} else
						*(dest++) = *(str2++);
					// Replace runs of consecutive slashes with a single slash character.
					if(*(dest-1)=='/' && *(dest-2)=='/')
						dest--;
					break;
				default:
					*(dest++) = *(str2++);
			}
		}
	}
	*dest='\0';

good:
	free(str1); free(begin_source);
	if(new_len)
		*new_len = dest - begin_dest;
	// printf("url_Normalize() END dest=[%s] len=%ld\n", begin_dest, dest-begin_dest);
	return(begin_dest);

bad:
	free(str1); free(begin_source);
	if(begin_dest)
		free(begin_dest);
	return(NULL);
}


/**
 * Percent-encode a string to be used as an URL. Return the encoded URL in a
 * newly allocated buffer of NULL if error. Reserved characters are not
 * encoded.
 * @param  src     Pointer to source string to be percent-encoded.
 * @param  len     Length of source string. If 0, strlen() will be used.
 * @param  new_len If not NULL, pointer to a long where the length of the new string will be stored.
 * @return         Pointer to newly allocated string. Must be freed with free().
 *                 Or NULL if error.
 */
extern char *url_Escape(const char *src, long len, long *new_len)
{
	const unsigned char *usrc = (unsigned char *)src;
	if(len==0)
		len = strlen(src);

	char *dest = malloc(3*len+1);
	if(dest==NULL)
		return(NULL);
	char *begin_dest = dest;

	while(*usrc) {
		if(*usrc<=32 || *usrc>=127 || *usrc=='#' || *usrc=='%') {
			sprintf(dest, "%%%02X", *(usrc++));
			dest +=3;
		} else {
			*(dest++) = *(usrc++);
		}
	}

	*dest='\0';

	if(new_len)
		*new_len = dest - begin_dest;
	return(begin_dest);	
}


/**
 * Percent-encode a string to be used as an URL, including all the reserved
 * characters defined in url_RFC3986_ReservedChars, while url_Escape() 
 * does not encode reserved characters). Return the encoded URL in a
 * newly allocated buffer of NULL if error. 
 * @param  src     Pointer to source string to be percent-encoded.
 * @param  len     Length of source string. If 0, strlen() will be used.
 * @param  new_len If not NULL, pointer to a long where the length of the new string will be stored.
 * @return         Pointer to newly allocated string. Must be freed with free().
 *                 Or NULL if error.
 */
extern char *url_EscapeIncludingReservedChars(const char *src, long len, long *new_len)
{
	const unsigned char *usrc = (unsigned char *)src;
	if(len==0)
		len = strlen(src);

	char *dest = malloc(3*len+1);
	if(dest==NULL)
		return(NULL);
	char *begin_dest = dest;

	while(*usrc) {
		if(*usrc<=32 || *usrc>=127 || *usrc=='%' || url_IsReserved((char)*usrc)) {
			sprintf(dest, "%%%02X", *(usrc++));
			dest +=3;
		} else {
			*(dest++) = *(usrc++);
		}
	}

	*dest='\0';

	if(new_len)
		*new_len = dest - begin_dest;
	return(begin_dest);	
}



/**
 * Canonicalize an URL as described in 
 * https://developers.google.com/safe-browsing/developers_guide_v3#Canonicalization.
 * Current limitation : no canonicalization of IP address is made. Reserved
 * characters "!*'();:@&=+$,/?#[]" are not encoded.
 * Return canonicalized URL is a newly allocated buffer, or NULL if error.
 * @param  src     Pointer to source string holding the URL to be canonicalized.
 * @param  len     Length of source string. If 0, strlen() will be used.
 * @param  new_len If not NULL, pointer to a long where the length of the new string will be stored.
 * @return         Pointer to newly allocated string holding the canonicalized URL,
 *                 or NULL if error. Must be freed with free().
 */
extern char *url_Canonicalize(const char *src, long len, long *new_len)
{
	long tmp;
	// printf("%-16s = [%s]\n", "SRC", src);
	if(new_len == NULL)
		new_len = &tmp;
	
	char *str3 = url_Normalize(src, len, new_len);
	if(str3 == NULL)
		return NULL;
	// printf("%-16s = [%s]\n", "NORMALIZED", str3);
	// printf("new_len = %ld\n", *new_len);	
	char *str4 = url_Escape(str3, *new_len, new_len);
	// printf("%-16s = [%s]\n", "ESCAPED", str4);
	// printf("new_len = %ld\n", *new_len);		

	free(str3);
	return(str4);
}


/**
 * Canonicalize an URL as described in 
 * https://developers.google.com/safe-browsing/developers_guide_v3#Canonicalization.
 * Current limitation : no canonicalization of IP address is made. Reserved
 * characters "!*'();:@&=+$,/?#[]" ARE encoded.
 * Return canonicalized URL is a newly allocated buffer, or NULL if error.
 * @param  src     Pointer to source string holding the URL to be canonicalized.
 * @param  len     Length of source string. If 0, strlen() will be used.
 * @param  new_len If not NULL, pointer to a long where the length of the new string will be stored.
 * @return         Pointer to newly allocated string holding the canonicalized URL,
 *                 or NULL if error. Must be freed with free().
 */
extern char *url_CanonicalizeWithFullEscape(const char *src, long len, long *new_len)
{
	long tmp;
	// printf("%-16s = [%s]\n", "SRC", src);
	if(new_len == NULL)
		new_len = &tmp;
	// char *str1 = url_RemoveTabCRLF(src, len, new_len);
	// printf("%-16s = [%s]\n", "CLEANED", str1);
	// printf("new_len = %ld\n", *new_len);
	// url_RemoveFragment(str1, new_len);
	// printf("%-16s = [%s]\n", "FRAGMENT REMOVED", str1);
	// printf("new_len = %ld\n", *new_len);	
	// char *str2 = url_Unescape(str1, *new_len, new_len);
	// printf("%-16s = [%s]\n", "UNESCAPED", str2);
	// printf("new_len = %ld\n", *new_len);		
	char *str3 = url_Normalize(src, len, new_len);
	// printf("%-16s = [%s]\n", "NORMALIZED", str3);
	// printf("new_len = %ld\n", *new_len);	
	char *str4 = url_EscapeIncludingReservedChars(str3, *new_len, new_len);
	// printf("%-16s = [%s]\n", "ESCAPED", str4);
	// printf("new_len = %ld\n", *new_len);		
	// free(str1);
	// free(str2);
	free(str3);
	return(str4);
}



/**
 * Encode a string to be compliant with application/x-www-form-urlencoded format.
 * It is the same as url_EscapeIncludingReservedChars() but it also replaces 
 * spaces with '+'.
 * @param  src     Pointer to string to be encoded.
 * @param  len     Length of string. If 0, strlen() will be used.
 * @param  new_len If not NULL, pointer to a long where the length of the 
 *                 encoded string will be stored.
 * @return         Pointer to newly allocated string holding 
 *                 or NULL if error. Must be freed with free().
 */
extern char *url_Encode(const char *src, long len, long *new_len)
{
	if(len==0)
		len = strlen(src);

	long length;

	// make sure URL is clean
	char *str = url_Unescape(src, len, &length);
	if(str==NULL)
		return(NULL);

	char *dest = malloc(3*length+1);
	if(dest==NULL)
		return(NULL);
	char *begin_dest = dest;

	unsigned char *usrc = (unsigned char *)str;
	while(*usrc) {
		if(*usrc<=32 || *usrc>=127 || *usrc=='%' || url_IsReserved((char)*usrc)) {
			sprintf(dest, "%%%02X", *(usrc++));
			dest +=3;
		} else if(*usrc==' ') {
			*(dest++) = '+';
			usrc++;
		} else {
			*(dest++) = *(usrc++);
		}
	}

	*dest='\0';

	free(str);

	if(new_len)
		*new_len = dest - begin_dest;
	return(begin_dest);	
}


/**
 * Parse a "key=value&key=value&key=value" string. The semicolon character (';') is
 * also an acceptable separator in lieu of "&".	The original string is modified :
 * '=', '&' and ';' characters are replaced by NUL. Each call return to next key-value
 * pair, as well as a pointer where the newt parsing has to be made. If the value part
 * was between double-quotes, those will be removed. If one part of the pair is missing,
 * the value found will be resturned as key. For example, when calling this function
 * with the string "0;URL=http://verifrom.com", the first call will returned "0" as key,
 * and NULL as value. The second call will return "URL" as key and "http://verifrom.com"
 * as value.
 * @param  string       String to be parsed.
 * @param  key_string   Pointer to a string pointer. Will be loaded with a pointer to
 *                      the beginning of the key-string in the initial string. Will be
 *                      NULL if no value found.
 * @param  value_string Pointer to a string pointer. Will be loaded with a pointer to
 *                      the beginning of the key-value in the initial string. Will be
 *                      NULL if no value found.
 * @return              Pointer to the remainder of the initial string to be parsed,
 *                      or NULL if there is nothing left to be parsed.
 */
extern char *url_ParseNextKeyValuePair(char *string, char **key_string, char **value_string)
{
    if(string==NULL || key_string==NULL || value_string==NULL) {
        // print_log(LOG_ERR, __FILE__, __LINE__, "common_ParseNextKeyValuePair() wrong arguments");
        return(NULL);
    }

    // for now, we found nothing
    *key_string = NULL;
    *value_string = NULL;

    // our index to parse string
    int ix=0;

    // strip leading blanks 
    while(string[ix]!=0 && !(isalnum(string[ix])))
        ix++;

    // we just found the start of the key_string
    (*key_string) = (string + ix);

    // if we reached the end of string, we must stop here
    if(string[ix]==0) 
        return(NULL);

    // accept all characters up to blanks or = or NUL or & OR ;
    ix++;
    while(string[ix]!=0 && (isalnum(string[ix])||string[ix]=='-'||string[ix]=='_') && string[ix]!=';' && string[ix]!='&')
        ix++;   

    // if we reached the end of string, we must stop here
    if(string[ix]==0) return(NULL);

    // remember the position so we can come back to put a NUL char here
    char *end_of_key_string = string+ix;

    // Look for a =
    while(string[ix]!=0 && string[ix]!='=' && string[ix]!='&' && string[ix]!=';')
        ix++;

    if(string[ix]==0) 
        return(NULL);

    if(string[ix]=='&' || string[ix]==';') {
    	(*end_of_key_string) = 0;
    	return(string[ix+1] ? string+ix+1 : NULL);
    }

    (*end_of_key_string) = 0;

    // Now we need to find the beginning of our value_string
    ix++;
    // while(string[ix]!=0 && !(string[ix]>=0x21 && string[ix]<=0x7E))
    //     ix++;       

    if(string[ix]==0) return(NULL);

    bool quoted_string = (string[ix]=='"');

    if(quoted_string) {
        ix++;
        (*value_string) = string+ix;
        while(string[ix]!=0 && string[ix]!='"')
            ix++;
    } else {
        (*value_string) = string+ix;
        ix++;
        while(string[ix]!=0 && string[ix]!='&' && string[ix]!=';')
            ix++;
    }

    if(string[ix]==0) return(NULL);

    // Mark end of value string
    string[ix]=0;

    return(string[ix+1] ? string+ix+1 : NULL);
}


/**
 * Split an URL into scheme, link, and query parts, as defined by RFC3986.
 * Warning : the original URL is modified (NUL characters are inserted to split
 * the original string in parts). Make sure the URL has been normalized before
 * calling this function.
 * @param url      URL to be split.
 * @param scheme   If not null, must be a pointer to a char*. Will be set to the beginning
 *                 of the scheme part in URL.
 * @param link     If not null, must be a pointer to a char*. Will be set to the beginning
 *                 of the link part in URL, or NULL or empty if none found.
 * @param query    If not null, must be a pointer to a char*. Will be set to the beginning
 *                 of the query part in URL, or NULL or empty if none found.
 */
extern void url_Split(char *url, char **scheme, char **link, char **query)
{
	if(url==NULL) {
		fprintf(stderr, "url_Split() invalid argument");
		return;
	}

	char *found_scheme=NULL, *found_link=NULL, *found_query=NULL;
	int pos=0;
	enum { BEGIN, AFTER_SCHEME, AFTER_LINK, AFTER_QUERY } state=BEGIN;

	while(url[pos]) {
		switch(url[pos]) {
			case ':':
				if(state==BEGIN) {
					found_scheme=url;
					state=AFTER_SCHEME;
					url[pos]='\0';
					found_link = url+pos+1;
				}
				break;
			case '?' :
				if(state==BEGIN || state==AFTER_SCHEME) {
					state=AFTER_LINK;
					url[pos]='\0';
					found_query = url+pos+1;							
				}
				break;
			// case '#' :
			// 	if(state==BEGIN || state==AFTER_SCHEME || state==AFTER_LINK) {
			// 		state=AFTER_QUERY;
			// 		url[pos]='\0';
			// 		found_fragment = url+pos+1;							
			// 	}
			// 	break;			
		}
		pos++;
	}

	if(found_link==NULL && found_scheme==NULL)
		found_link=url;

	if(scheme)   *scheme   = found_scheme;
	if(link)     *link     = found_link;
	if(query)    *query    = found_query;
	// if(fragment) *fragment = found_fragment;

	// if(found_scheme)   printf("url_Split() scheme=[%s]\n", found_scheme);
	// if(found_link)     printf("url_Split() link=[%s]\n", found_link);
	// if(found_query)    printf("url_Split() query=[%s]\n", found_query);
	// if(found_fragment) printf("url_Split() fragment=[%s]\n", found_fragment);

}


/**
 * Return the hostname part extracted from an url in a newly allocated string.
 * @param  url     Pointer to an URL.
 * @return         Pointer to a newly allocated string holding the hostname
 *                 extracted from the URL. Use free() to deallocate the memory.
 */
extern char *url_GetHostname(const char *url)
{
	// Make sure we have an url
	if(url==NULL)
		return(NULL);

	// Make sure we have a normalized url
	char *clean = url_Normalize(url, 0, NULL);
	if(clean==NULL)
		return(NULL);
	// printf("url_GetHostname() clean=[%s]\n", clean);

	// Find the link part of the url
	char *link;
	url_Split(clean, NULL, &link, NULL);

	if(link==NULL) {
		fprintf(stderr, "url_GetHostname() cannot find link part in URL [%s]\n", url);
		free(clean);
		return(NULL);
	}

	// Skip leading '//'
	link +=2;

	// Find the end of the hostname in link, that
	// is the firt '/' we meet.
 	for(char *p=link; *p; p++)
		if(*p == '/') {
			*p = '\0';
			break;
		}
	// printf("url_GetHostname() link=[%s]\n", link);

	// Make a copy of the hostname
	char *hostname = url_Encode(link, 0, NULL);
	// printf("url_GetHostname() hostname=[%s]\n", hostname);

	// Free the cleaned url we created
	free(clean);

	// Return hostname
	return(hostname);

}


/**
 * Return the base part of an URL in a newly allocated string.
 * @param  url     Pointer to string holding the URL.
 * @param  len     Length of URL, strlen() will be used if 0.
 * @param  new_len If not NULL, pointer to a long where the length of the new
 *                 string will be stored.
 * @return         Pointer to a newly allocated string holding the
 *                 base part of the initial URL.
 */
extern char *url_GetBase(const char *url, long len, long *new_len)
{
	if(len == 0)
		len = strlen(url);

	long tmp=0;
	if(new_len == NULL)
		new_len = &tmp;

	char *str = url_Normalize(url, len, NULL);
	if(str==NULL)
		return(NULL);
	url_RemoveQuery(str, new_len);

	// Remove the last part of the URL until we found a '/'
	char *end = str + *new_len - 1;
	for( ; end-str>=0 && *end!='/'; end--)
		;
	*(++end) = '\0';

	*new_len = end - str;

	return(str);
}
