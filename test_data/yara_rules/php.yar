rule NonPrintableChars
{
    strings:
        $non_printables = /(function|return|base64_decode).{,256}[^\x09-\x0d\x20-\x7E]{3}/

    condition:
        any of them
}

rule PasswordProtection
{
    strings:
        $md5 = /md5\s*\(\s*\$_(GET|REQUEST|POST|COOKIE|SERVER)[^)]+\)\s*===?\s*['"][0-9a-f]{32}['"]/ nocase
        $sha1 = /sha1\s*\(\s*\$_(GET|REQUEST|POST|COOKIE|SERVER)[^)]+\)\s*===?\s*['"][0-9a-f]{40}['"]/ nocase

    condition:
        any of them
}

rule ObfuscatedPhp
{
    strings:
        $eval = /(<\?php|[;{}])[ \t]*@?(eval|preg_replace|system|assert|passthru|(pcntl_)?exec|shell_exec|call_user_func(_array)?)\s*\(/ nocase
        $eval_comment = /(eval|preg_replace|system|assert|passthru|(pcntl_)?exec|shell_exec|call_user_func(_array)?)\/\*[^\*]*\*\/\(/ nocase
        $b374k = "'ev'.'al'"
        $align = /(\$\w+=[^;]*)*;\$\w+=@?\$\w+\(/
        $weevely3 = /\$\w=\$[a-zA-Z]\('',\$\w\);\$\w\(\);/
        $c99_launcher = /;\$\w+\(\$\w+(,\s?\$\w+)+\);/
        $nano = /\$[a-z0-9-_]+\[[^]]+\]\(/
        $ninja = /base64_decode[^;]+getallheaders/
        $variable_variable = /\${\$[0-9a-zA-z]+}/
        $variable_variable2 = /(@?\$\s*\w+\s*\(){3,}[^;]+/
        $too_many_chr = /(chr\([\d]+\)\.){8}/
        $too_many_chr2 = /(chr[^.]+\.|substr[^.]+\.){4,}[^;]+/ nocase
        $concat = /(\$[^\n\r]+\.){5}/
        $concat_with_spaces = /(\$[^\n\r]+\. ){5}/
        $concat_with_dots = /(\s*(\"|\')\s*\w+\s*(\"|\')\s*\.){5}/
        $concat_with_dots2 = /(\([^.]+\.){6}/
        $var_as_func = /\$_(GET|POST|COOKIE|REQUEST|SERVER)\s*\[[^\]]+\]\s*\(/
        $var_as_func2 = /\$\s*(\w+|\{\s*\w+\s*\})\s*(\(|\{)\s*\$[^;]+;[^=?]*\?>/

    condition:
        any of them
}

rule special_types
{
    strings:
        $ = "6776666E286763736A38346466656871646A2A2464524F58565B2C7C302C5F292E" nocase
        $ = "greeting: !{$str}"
        $ = "~\xbe\xac\xac\xba\xad\xab" nocase

    condition:
        any of them
}

rule mal_types
{
    strings:
        $mal_user_func = /\b(call_user_func(_array)?)\s*\(\s*create_function/ nocase
        $mal_dolar_ = /\$(\w+)\s*\(\$(\w){1,}\[\$(\w){1,}[^;]+;/
        $mal_array = /\$array\s*(\[[^\]]+\]){1,}\(\s*\$[^;]+;[^=?]*\?>/ nocase
        $mal_class = /(eval|assert|passthru|exec|include|require|require_once|system|pcntl_exec|shell_exec|`|ob_start)\s*\(\$this-\>[^;]+;/ nocase
        $mal_include = /(include|require(_once)?)\s*\(\s*\$[^;]+;/
        $mal_xor = /([^=]*=?\s*(\'[^']+\'|\"[^"]+\"|\w+)\s*(\||\^|&|!)\s*(\'[^']+\'|\"[^"]+\"|\w+)[^;\n]+;?\s*){5}/
        $mal_filename = /\$[^=]+=\s*(substr|strrev|substr_replace|str_rot13|base64_decode|\$\w+)\(\s*__FILE__[^;]+;/ nocase
        $mal_xml = /\<xsl\s*:\s*value-of(\s*[^\s]*)*select[^:]*:?\s*function\s*\(['"](eval|assert|passthru|exec|include|require|require_once|system|pcntl_exec|shell_exec|ob_start)[^>\n]+\>?/ nocase
        $mal_symbs = /[^\w\s]{100}/
        $mal_base64 = /(=[^"']*["'][0-9a-zA-Z+\/]+={1,2}['"][^=]+){5}/
        $mal_encoding = /[~&\^\|]\s*(\\x[a-f]{2}){5, }/ nocase

    condition:
        any of them
}

rule DodgyPhp
{
    strings:
        $basedir_bypass = /curl_init\s*\(\s*["']file:\/\// nocase
        $basedir_bypass2 = "file:file:///"
        $disable_magic_quotes = /set_magic_quotes_runtime\s*\(\s*0/ nocase
        $execution = /\b(eval|assert|passthru|exec|include|require|require_once|system|pcntl_exec|shell_exec|base64_decode|`|ob_start|call_user_func(_array)?)\s*\(\s*([^.]+\.)?(base64_decode|php:\/\/input|str_rot13|gz(inflate|uncompress)|getenv|pack|\\?\$_(GET|REQUEST|POST|COOKIE|SERVER))/ nocase
        $execution2 = /\b(array_map|array_filter|array_reduce|array_walk(_recursive)?|array_walk|assert_options|uasort|uksort|usort|preg_replace_callback|iterator_apply|mb_ereg_replace|preg_filter|register_shutdown_function|register_tick_function)\s*\(\s*[^,]*,?\s*(substr_replace|strrev|base64_decode|php:\/\/input|str_rot13|gz(inflate|uncompress)|getenv|pack|\\?\$_(GET|REQUEST|POST|COOKIE|SERVER))/ nocase
        $execution3 = /\b(array_(diff|intersect)_u(key|assoc)|array_udiff|forward_static_call_array)([^,]+){0,1}[^$]+\$_[^;]+;/ nocase
        $execution4 = /\b(array_(diff|intersect)_u(key|assoc)|array_udiff|forward_static_call_array)([^,]+){0,1}[^$]+\$_[^;]+;/ nocase
        $execution5 = /\b(eval|assert|passthru|exec|include|system|pcntl_exec|shell_exec|base64_decode|`|array_map|ob_start|call_user_func(_array)?|array_map|array_filter|array_reduce|array_walk(_recursive)?|array_walk|assert_options|uasort|uksort|usort|preg_replace_callback|iterator_apply|mb_ereg_replace|preg_filter|register_shutdown_function|register_tick_function)([^,]+,)*[^;]+;[^=?]*\?>/ nocase
        $htaccess = "SetHandler application/x-httpd-php"
        $iis_com = /IIS:\/\/localhost\/w3svc/
        $include = /include\s*\(\s*[^\.]+\.(png|jpg|gif|bmp)/
        $ini_get = /ini_(get|set|restore)\s*\(\s*['"](safe_mode|open_basedir|disable_(function|classe)s|safe_mode_exec_dir|safe_mode_include_dir|register_globals|allow_url_include)/ nocase
        $pr = /(preg_replace(_callback)?|mb_ereg_replace|preg_filter)\s*\(.+(\/|\\x2f)(e|\\x65)['"]/  nocase
        $register_function = /register_[a-z]+_function\s*\(\s*['"]\s*(eval|assert|passthru|exec|include|system|shell_exec|`)/
        $safemode_bypass = /\x00\/\.\.\/|LD_PRELOAD/
        $shellshock = /\(\)\s*{\s*[a-z:]\s*;\s*}\s*;/
        $udp_dos = /fsockopen\s*\(\s*['"]udp:\/\// nocase
        $various = "<!--#exec cmd="
        $at_eval = /@eval\s*\(/ nocase
        $double_var = /\${\s*\${/
        $extract = /extract\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)/
        $reversed = /noitcnuf_etaerc|metsys|urhtssap|edulcni|etucexe_llehs/ nocase
        $silenced_include =/@\s*include\s*/ nocase

    condition:
        any of them
}

rule DangerousPhp
{
    strings:
        $system = "system" fullword nocase
        $ = "assert" fullword nocase
        $ = "backticks" fullword nocase
        $ = "call_user_func" fullword nocase
        $ = "eval" fullword nocase
        $ = "exec" fullword nocase
        $ = "fpassthru" fullword nocase
        $ = "fsockopen" fullword nocase
        $ = "function_exists" fullword nocase
        $ = "getmygid" fullword nocase
        $ = "shmop_open" fullword nocase
        $ = "mb_ereg_replace_callback" fullword nocase
        $ = "passthru" fullword nocase
        $ = /pcntl_(exec|fork)/ fullword nocase
        $ = "php_uname" fullword nocase
        $ = "phpinfo" fullword nocase
        $ = "posix_geteuid" fullword nocase
        $ = "posix_getgid" fullword nocase
        $ = "posix_getpgid" fullword nocase
        $ = "posix_getppid" fullword nocase
        $ = "posix_getpwnam" fullword nocase
        $ = "posix_getpwuid" fullword nocase
        $ = "posix_getsid" fullword nocase
        $ = "posix_getuid" fullword nocase
        $ = "posix_kill" fullword nocase
        $ = "posix_setegid" fullword nocase
        $ = "posix_seteuid" fullword nocase
        $ = "posix_setgid" fullword nocase
        $ = "posix_setpgid" fullword nocase
        $ = "posix_setsid" fullword nocase
        $ = "posix_setsid" fullword nocase
        $ = "posix_setuid" fullword nocase
        $ = "preg_replace_callback" fullword
        $ = "proc_open" fullword nocase
        $ = "proc_close" fullword nocase
        $ = "popen" fullword nocase
        $ = "register_shutdown_function" fullword nocase
        $ = "register_tick_function" fullword nocase
        $ = "shell_exec" fullword nocase
        $ = "shm_open" fullword nocase
        $ = "show_source" fullword nocase
        $ = "socket_create(AF_INET, SOCK_STREAM, SOL_TCP)" nocase
        $ = "socket_read" nocase
        $ = "stream_socket_pair" nocase
        $ = "suhosin.executor.func.blacklist" nocase
        $ = "unregister_tick_function" fullword nocase
        $ = "win32_create_service" fullword nocase
        $ = "xmlrpc_decode" fullword nocase
        $ = /ob_start\s*\(\s*[^\)]/
        $ = "curl_exec" nocase
        $whitelist = /escapeshellcmd|escapeshellarg/ nocase

    condition:
        not $whitelist and (3 of them or #system > 250)
}