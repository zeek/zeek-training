/*
Language: Zeek
Author: Lily Foster <lily@lily.flowers>
Description: Zeek is a programming language designed specifically to be able to represent network-related abstractions (e.g. addresses and ports) and as such offers a great deal of functionality and flexibility in terms of helping you accomplish your network-monitoring goals.
Category: misc
*/

module.exports = function(hljs) {
  var HEX = '[0-9a-fA-F_]';
  var FLOAT = '((\\d*\\.?\\d+)|(\\d+\\.?\\d*))([eE][-+]?\\d+)?';
  var H = '[A-Za-z0-9][-A-Za-z0-9]*';

  var KEYWORDS = {
    keyword:
      'const event|10 export function global hook|10 module option redef type ' +

      'addr|10 any|10 bool count counter double enum file int interval ' +
      'opaque|10 pattern|10 port|10 record set string subnet|10 table time ' +
      'timer vector ' +

      'local|10 add delete print for while next|10 break if else switch case ' +
      'default break fallthrough|10 when|10 schedule|10 return ' +

      'in is as of',

    literal:
       'T F'
  };

  var PREPROC = {
    className: 'meta',
    begin:
      '^\\s*@(deprecated|load|load-plugin|load-sigs|unload|prefixes|if|' +
      'ifdef|ifndef|else|endif)\\b', end: '$',
    contains: [
      {
        className: 'meta-string',
        begin: '"', end: '"',
        illegal: '\\n',
        contains: [hljs.BACKSLASH_ESCAPE]
      },
      {
        className: 'meta-keyword',
        begin: '\\b(T|F)\\b'
      }
    ]
  };

  var META = {
    className: 'meta',
    begin: '@(DEBUG|DIR|FILENAME)\\b'
  };

  var ATTRIBUTE = {
    className: 'attribute',
    begin:
      '&(redef|priority|log|optional|default|add_func|' +
      'delete_func|expire_func|read_expire|write_expire|' +
      'create_expire|synchronized|persistent|rotate_interval|' +
      'rotate_size|encrypt|raw_output|mergeable|error_handler|' +
      'type_column|deprecated)\\b',
    relevance: 10
  };

  var PORT = {
    className: 'number',
    begin: '\\b\\d+/(tcp|udp|icmp|unknown)\\b',
    relevance: 10
  };

  var ADDRESS = {
    className: 'number',
    variants: [
      {begin: '\\[(' + HEX + '{0,4}:){1,6}(' + HEX + '{0,4}:' + HEX + '{0,4}|(\\d+\\.){3}\\d+)\\](/\\d+\\b)?'},
      {begin: '\\b(\\d+\\.){3}\\d+(/\\d+)?\\b'}
    ]
  };

  var HOST = {
    className: 'string',
    begin: '\\b' + H + '(\\.' + H + ')+\\b',
    relevance: 0
  };

  var TIME = {
    className: 'number',
    begin: '\\b' + FLOAT + '\\s*(day|hr|min|sec|msec|usec)s?\\b'
  };

  var PATTERN = {
    begin: '(' + hljs.RE_STARTERS_RE + '|\\b(print|case|return)\\b)\\s*',
    keywords: 'print case return',
    contains: [
      hljs.HASH_COMMENT_MODE,
      hljs.REGEXP_MODE
    ],
    relevance: 0
  };

  var DECL = {
    beginKeywords:
      'const global module option redef type', end: '\\s*;', excludeEnd: true,
    keywords: KEYWORDS,
    contains: [
      PREPROC,
      hljs.HASH_COMMENT_MODE,
      {
        className: 'title',
        beginKeywords: 'type', end: '\\s*:', excludeBegin: true, excludeEnd: true
      },
      META,
      ATTRIBUTE,
      PORT,
      ADDRESS,
      HOST,
      TIME,
      hljs.C_NUMBER_MODE,
      PATTERN,
      hljs.QUOTE_STRING_MODE
    ],
    relevance: 0
  };

  var CALL = {
    beginKeywords: 'event hook', end: '\\s*;', excludeEnd: true,
    keywords: KEYWORDS,
    contains: [
      PREPROC,
      hljs.HASH_COMMENT_MODE,
      META,
      ATTRIBUTE,
      PORT,
      ADDRESS,
      HOST,
      TIME,
      hljs.C_NUMBER_MODE,
      PATTERN,
      hljs.QUOTE_STRING_MODE
    ],
    relevance: 10
  };

  var BODY = {
    begin: '\\{',
    end: '\\}',
    keywords: KEYWORDS,
    contains: [
      PREPROC,
      hljs.HASH_COMMENT_MODE,
      META,
      ATTRIBUTE,
      PORT,
      ADDRESS,
      HOST,
      TIME,
      hljs.C_NUMBER_MODE,
      PATTERN,
      hljs.QUOTE_STRING_MODE,
      CALL,
      'self'
    ],
    relevance: 0
  };

  var FUNC = {
    className: 'function',
    beginKeywords: 'event function hook', end: '\\s*\\{', excludeEnd: true,
    keywords: KEYWORDS,
    contains: [
      PREPROC,
      hljs.HASH_COMMENT_MODE,
      {
        className: 'params',
        begin: '\\(', end: '\\)', excludeBegin: true, excludeEnd: true,
        keywords: KEYWORDS,
        contains: [
          META,
          ATTRIBUTE,
          PORT,
          ADDRESS,
          HOST,
          TIME,
          hljs.C_NUMBER_MODE,
          PATTERN,
          hljs.QUOTE_STRING_MODE,
        ],
        relevance: 0
      },
      META,
      ATTRIBUTE,
      PORT,
      ADDRESS,
      HOST,
      TIME,
      hljs.C_NUMBER_MODE,
      PATTERN,
      hljs.QUOTE_STRING_MODE,
      hljs.TITLE_MODE
    ],
    starts: BODY,
    relevance: 0
  };
    
  return {
    aliases: ['zeek'],
    illegal: '</',
    keywords: KEYWORDS,
    contains: [
      PREPROC,
      hljs.HASH_COMMENT_MODE,
      META,
      ATTRIBUTE,
      PORT,
      ADDRESS,
      HOST,
      TIME,
      hljs.C_NUMBER_MODE,
      PATTERN,
      hljs.QUOTE_STRING_MODE,
      DECL,
      FUNC
    ]
  };
}
