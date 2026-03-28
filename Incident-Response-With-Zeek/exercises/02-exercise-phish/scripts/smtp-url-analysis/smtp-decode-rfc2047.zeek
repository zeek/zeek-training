##! RFC 2047 Encoded-Word Decoder for SMTP Subject Headers
##!
##! Decodes MIME encoded-words (=?charset?encoding?encoded-text?=) found in
##! SMTP Subject headers, supporting both B (Base64) and Q (Quoted-Printable)
##! transfer encodings as defined in RFC 2047.
##!
##! The decoded subject is added to the SMTP log as ``decoded_subject``.
##!
##! Known limitations:
##!   - Charset conversion is not performed; output is raw decoded bytes.
##!     Non-UTF-8 charsets (ISO-8859-1, GB2312, etc.) will not render correctly.
##!   - Only the Subject header is decoded. From/To display names are not handled.
##!
##! Reference: https://www.rfc-editor.org/rfc/rfc2047

@load base/protocols/smtp

module SMTP;

export {
    #Helper for decoding RFC 2047 encoded-word text in script code/tests.
    global decode_encoded_word: function(raw: string): string;
}

#Pattern matching RFC 2047 encoded-words: =?charset?encoding?encoded-text?=
#  charset:      one or more chars excluding ? and whitespace
#  encoding:     B or Q (case-insensitive)
#  encoded-text: one or more chars excluding ? and whitespace
const encoded_word_pat = /\=\?[^\?[:space:]]+\?[bBqQ]\?[^\?[:space:]]+\?\=/;

#Decode RFC 2047 Q-encoding (Quoted-Printable variant).
#
#Rules per RFC 2047 §4.2:
#  - ``_`` represents ASCII space (0x20)
#  - ``=XX`` represents the byte with hex value XX
#  - All other printable ASCII passes through literally
#
#encoded_text: the raw encoded-text portion (between ?Q? and ?=).
#
#Returns: the decoded string.
function decode_q_encoding(encoded_text: string): string
    {
    # Replace underscores with spaces (RFC 2047 §4.2 rule 2)
    local text = gsub(encoded_text, /_/, " ");

    #Split on hex escape sequences, preserving them.
    #Even indices = literal text, odd indices = =XX hex escapes.

    local q_parts = split_string_all(text, /\=[a-fA-F0-9]{2}/);

    for ( f in q_parts )
        {
        #Odd indices are the =XX hex escapes — decode them
        if ( f % 2 == 1 )
            {
            # Convert =XX to %XX for unescape_URI compatibility
            q_parts[f] = sub(q_parts[f], /^=/, "%");
            q_parts[f] = unescape_URI(q_parts[f]);
            }
        }

    return join_string_vec(q_parts, "");
    }

#Extract the encoded-text portion from a full encoded-word token.
#
#Input:  ``=?charset?X?encoded-text?=``
#Output: the ``encoded-text`` portion only.
#
#Uses greedy prefix strip (=?charset?X?) and suffix strip (?=).
function extract_encoded_text(ew: string): string
    {
    local text = gsub(ew, /(^=\?[^\?[:space:]]+\?[bBqQ]\?|\?\=$)/, "");
    return text;
    }

#Decode a header value containing one or more RFC 2047 encoded-words.
#
#Handles:
#  - Mixed encoded-word and plain-text segments
#  - Adjacent encoded-words with intervening whitespace (stripped per §6.2)
#  - Both B (Base64) and Q (Quoted-Printable) encodings
#
#raw: the raw header value potentially containing encoded-words.
#
#Returns: the decoded string. If no encoded-words are found, returns
#         the original value unchanged.
function decode_encoded_word(raw: string): string
    {
    #Split into alternating [plain, encoded-word, plain, ...] segments.
    #Even indices (0, 2, 4...) = non-matching (plain text / whitespace)
    #Odd indices  (1, 3, 5...) = matching (full encoded-word tokens)

    local parts = split_string_all(raw, encoded_word_pat);
    local num_parts = |parts|;

    #No encoded-words found — return as-is

    if ( num_parts <= 1 )
        return raw;

    for ( i in parts )
        {
        #Only decode odd-indexed segments (the encoded-word matches)
        if ( i % 2 == 0 )
            next;

        local encoded_text = extract_encoded_text(parts[i]);

        if ( /\?[bB]\?/ in parts[i] )
            {
            #B-encoding: standard Base64
            parts[i] = decode_base64(encoded_text);
            }
        else if ( /\?[qQ]\?/ in parts[i] )
            {
            #Q-encoding: Quoted-Printable variant
            parts[i] = decode_q_encoding(encoded_text);
            }
        }

    #RFC 2047 §6.2: Linear whitespace between adjacent encoded-words
    #must be ignored in the decoded output. A non-matching segment
    #(even index) that is purely whitespace and sits between two
    #encoded-word segments (odd indices on both sides) is discarded.

    local result_parts: string_vec;
    for ( i in parts )
        {
        if ( i % 2 == 0 && i > 0 && i < num_parts - 1 )
            {
            if ( /^[[:blank:][:space:]]*$/ in parts[i] )
                next;
            }
        result_parts += parts[i];
        }

    return join_string_vec(result_parts, "");
    }

#Extend the SMTP::Info record with the decoded subject field.
redef record SMTP::Info += {
    #The RFC 2047 decoded subject line. Only populated when the raw
    #Subject header contains encoded-words (=?charset?encoding?text?=).

    decoded_subject: string &optional &log;
};

#Decode encoded-words in the Subject header and attach to the SMTP log.
#Priority 3 ensures this runs after Zeek's built-in SMTP analysis has
#populated c$smtp, but before most user-defined handlers at default priority.
event mime_one_header(c: connection, h: mime_header_rec) &priority=3
    {
    if ( ! c?$smtp )
        return;

    if ( to_upper(h$name) != "SUBJECT" )
        return;

    #Only attempt decoding if encoded-word markers are present
    if ( encoded_word_pat !in h$value )
        return;

    c$smtp$decoded_subject = decode_encoded_word(h$value);
    }
