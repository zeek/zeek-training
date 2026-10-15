// This is largely based on https://github.com/orgs/marp-team/discussions/422

const { Marp } = require('@marp-team/marp-core')
const hljs = require('highlight.js')
const zeekLang = require('./highlightjs-zeek.js');

hljs.registerLanguage('zeek', zeekLang);

// Customize the commands the bash highlighter considers "built-ins".  This is a
// bit silly -- it could just parse out commands more generally and precisely.
// This highlighter is very imprecise for shell commands.

const bashLang = hljs.getLanguage('bash');

if (bashLang && bashLang.keywords) {
    const customCmds = ['docker', 'git', 'jq', 'ping', 'systemctl',
                        'zeek', 'zeekctl', 'zeek-cut', 'zkg'];

    // These trigger when we don't want them to:
    const notCmds = new Set(['clone', 'exec']);

    const existingBuiltIns = Array.isArray(bashLang.keywords.built_in)
          ? bashLang.keywords.built_in
          : bashLang.keywords.built_in.split(' ');

    const cmdSet = new Set([...existingBuiltIns, ...customCmds]).difference(notCmds);
    
    bashLang.keywords.built_in = [...cmdSet];
}

class CustomMarp extends Marp {
    constructor(opts) {
        super(opts);
    }

    highlighter(code, lang, _attrs) {
        if (lang && hljs.getLanguage(lang)) {
            return hljs.highlight(code, {
                language: lang,
                ignoreIllegals: true,
            }).value
        }
        return ''
    }
}

module.exports = CustomMarp
