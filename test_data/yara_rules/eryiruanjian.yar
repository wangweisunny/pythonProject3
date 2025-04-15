rule Malware_Detection
{
    meta:
        description = "Detects common malicious software patterns"
        author = "Your Name"
        date = "2024-11-12"
        version = "1.0"

    strings:
        // WebShell检测
        $webshell_eval = /eval\s*\(\s*base64_decode\s*\(/ nocase
        $webshell_system = /system\s*\(\s*[$_A-Z]+\['[A-Z_]+\']\s*\)/ nocase
        $webshell_exec = /exec\s*\(\s*[$_A-Z]+\['[A-Z_]+\']\s*\)/ nocase
        $webshell_shell_exec = /shell_exec\s*\(\s*[$_A-Z]+\['[A-Z_]+\']\s*\)/ nocase
        $webshell_passthru = /passthru\s*\(\s*[$_A-Z]+\['[A-Z_]+\']\s*\)/ nocase
        $webshell_preg_replace = /preg_replace\s*\(\s*['"][/e]['"]\s*,\s*[$_A-Z]+\['[A-Z_]+\']\s*,\s*[$_A-Z]+\['[A-Z_]+\']\s*\)/ nocase
        $webshell_assert = /assert\s*\(\s*[$_A-Z]+\['[A-Z_]+\']\s*\)/ nocase
        $webshell_create_function = /create_function\s*\(\s*[$_A-Z]+\['[A-Z_]+\']\s*,\s*[$_A-Z]+\['[A-Z_]+\']\s*\)/ nocase
        $webshell_call_user_func = /call_user_func\s*\(\s*[$_A-Z]+\['[A-Z_]+\']\s*\)/ nocase
        $webshell_call_user_func_array = /call_user_func_array\s*\(\s*[$_A-Z]+\['[A-Z_]+\']\s*,\s*[$_A-Z]+\['[A-Z_]+\']\s*\)/ nocase
        $webshell_php_input = /php\s*:\s*\/\/\s*input\s*[^>]+/ nocase
        $webshell_gzinflate = /gzinflate\s*\(\s*base64_decode\s*\(/ nocase
        $webshell_strrev = /strrev\s*\(\s*[^)]+\s*\)/ nocase
        $webshell_base64_decode = /base64_decode\s*\(\s*[^)]+\s*\)/ nocase
        $webshell_file_put_contents = /file_put_contents\s*\(\s*[$_A-Z]+\['[A-Z_]+\']\s*,\s*[$_A-Z]+\['[A-Z_]+\']\s*\)/ nocase
        $webshell_file_get_contents = /file_get_contents\s*\(\s*[$_A-Z]+\['[A-Z_]+\']\s*\)/ nocase
        $webshell_fopen = /fopen\s*\(\s*[$_A-Z]+\['[A-Z_]+\']\s*,\s*['"]w['"]\s*\)/ nocase
        $webshell_fwrite = /fwrite\s*\(\s*[$_A-Z]+\['[A-Z_]+\']\s*,\s*[$_A-Z]+\['[A-Z_]+\']\s*\)/ nocase
        $webshell_fclose = /fclose\s*\(\s*[$_A-Z]+\['[A-Z_]+\']\s*\)/ nocase
        $webshell_move_uploaded_file = /move_uploaded_file\s*\(\s*[$_A-Z]+\['[A-Z_]+\']\s*,\s*[$_A-Z]+\['[A-Z_]+\']\s*\)/ nocase
        $webshell_unlink = /unlink\s*\(\s*[$_A-Z]+\['[A-Z_]+\']\s*\)/ nocase
        $webshell_chmod = /chmod\s*\(\s*[$_A-Z]+\['[A-Z_]+\']\s*,\s*\d+\s*\)/ nocase
        $webshell_chown = /chown\s*\(\s*[$_A-Z]+\['[A-Z_]+\']\s*,\s*[$_A-Z]+\['[A-Z_]+\']\s*\)/ nocase
        $webshell_chgrp = /chgrp\s*\(\s*[$_A-Z]+\['[A-Z_]+\']\s*,\s*[$_A-Z]+\['[A-Z_]+\']\s*\)/ nocase
        $webshell_touch = /touch\s*\(\s*[$_A-Z]+\['[A-Z_]+\']\s*\)/ nocase
        $webshell_mkdir = /mkdir\s*\(\s*[$_A-Z]+\['[A-Z_]+\']\s*,\s*\d+\s*\)/ nocase
        $webshell_rmdir = /rmdir\s*\(\s*[$_A-Z]+\['[A-Z_]+\']\s*\)/ nocase
        $webshell_rename = /rename\s*\(\s*[$_A-Z]+\['[A-Z_]+\']\s*,\s*[$_A-Z]+\['[A-Z_]+\']\s*\)/ nocase
        $webshell_copy = /copy\s*\(\s*[$_A-Z]+\['[A-Z_]+\']\s*,\s*[$_A-Z]+\['[A-Z_]+\']\s*\)/ nocase
        $webshell_symlink = /symlink\s*\(\s*[$_A-Z]+\['[A-Z_]+\']\s*,\s*[$_A-Z]+\['[A-Z_]+\']\s*\)/ nocase
        $webshell_link = /link\s*\(\s*[$_A-Z]+\['[A-Z_]+\']\s*,\s*[$_A-Z]+\['[A-Z_]+\']\s*\)/ nocase
        $webshell_readlink = /readlink\s*\(\s*[$_A-Z]+\['[A-Z_]+\']\s*\)/ nocase
        $webshell_realpath = /realpath\s*\(\s*[$_A-Z]+\['[A-Z_]+\']\s*\)/ nocase
        $webshell_file_exists = /file_exists\s*\(\s*[$_A-Z]+\['[A-Z_]+\']\s*\)/ nocase
        $webshell_is_file = /is_file\s*\(\s*[$_A-Z]+\['[A-Z_]+\']\s*\)/ nocase
        $webshell_is_dir = /is_dir\s*\(\s*[$_A-Z]+\['[A-Z_]+\']\s*\)/ nocase
        $webshell_is_readable = /is_readable\s*\(\s*[$_A-Z]+\['[A-Z_]+\']\s*\)/ nocase
        $webshell_is_writable = /is_writable\s*\(\s*[$_A-Z]+\['[A-Z_]+\']\s*\)/ nocase
        $webshell_is_executable = /is_executable\s*\(\s*[$_A-Z]+\['[A-Z_]+\']\s*\)/ nocase
        $webshell_filesize = /filesize\s*\(\s*[$_A-Z]+\['[A-Z_]+\']\s*\)/ nocase
        $webshell_filetype = /filetype\s*\(\s*[$_A-Z]+\['[A-Z_]+\']\s*\)/ nocase
        $webshell_fileperms = /fileperms\s*\(\s*[$_A-Z]+\['[A-Z_]+\']\s*\)/ nocase
        $webshell_fileatime = /fileatime\s*\(\s*[$_A-Z]+\['[A-Z_]+\']\s*\)/ nocase
        $webshell_filemtime = /filemtime\s*\(\s*[$_A-Z]+\['[A-Z_]+\']\s*\)/ nocase
        $webshell_filectime = /filectime\s*\(\s*[$_A-Z]+\['[A-Z_]+\']\s*\)/ nocase
        $webshell_fileinode = /fileinode\s*\(\s*[$_A-Z]+\['[A-Z_]+\']\s*\)/ nocase
        $webshell_filegroup = /filegroup\s*\(\s*[$_A-Z]+\['[A-Z_]+\']\s*\)/ nocase
        $webshell_fileowner = /fileowner\s*\(\s*[$_A-Z]+\['[A-Z_]+\']\s*\)/ nocase

        // 命令执行木马
        $cmdshell_system = /system\s*\(\s*[$_A-Z]+\['[A-Z_]+\']\s*\)/ nocase
        $cmdshell_exec = /exec\s*\(\s*[$_A-Z]+\['[A-Z_]+\']\s*\)/ nocase
        $cmdshell_shell_exec = /shell_exec\s*\(\s*[$_A-Z]+\['[A-Z_]+\']\s*\)/ nocase
        $cmdshell_passthru = /passthru\s*\(\s*[$_A-Z]+\['[A-Z_]+\']\s*\)/ nocase
        $cmdshell_assert = /assert\s*\(\s*[$_A-Z]+\['[A-Z_]+\']\s*\)/ nocase
        $cmdshell_call_user_func = /call_user_func\s*\(\s*[$_A-Z]+\['[A-Z_]+\']\s*\)/ nocase

        // 上传木马
        $uploadshell_move_uploaded_file = /move_uploaded_file\s*\(\s*[$_A-Z]+\['[A-Z_]+\']\s*,\s*[$_A-Z]+\['[A-Z_]+\']\s*\)/ nocase
        $uploadshell_file_put_contents = /file_put_contents\s*\(\s*[$_A-Z]+\['[A-Z_]+\']\s*,\s*[$_A-Z]+\['[A-Z_]+\']\s*\)/ nocase
        $uploadshell_fwrite = /fwrite\s*\(\s*[$_A-Z]+\['[A-Z_]+\']\s*,\s*[$_A-Z]+\['[A-Z_]+\']\s*\)/ nocase
        $uploadshell_fopen = /fopen\s*\(\s*[$_A-Z]+\['[A-Z_]+\']\s*,\s*['"]w['"]\s*\)/ nocase

        // 后门木马
        $backdoor_eval = /eval\s*\(\s*base64_decode\s*\(/ nocase
        $backdoor_system = /system\s*\(\s*[$_A-Z]+\['[A-Z_]+\']\s*\)/ nocase
        $backdoor_exec = /exec\s*\(\s*[$_A-Z]+\['[A-Z_]+\']\s*\)/ nocase
        $backdoor_shell_exec = /shell_exec\s*\(\s*[$_A-Z]+\['[A-Z_]+\']\s*\)/ nocase
        $backdoor_passthru = /passthru\s*\(\s*[$_A-Z]+\['[A-Z_]+\']\s*\)/ nocase
        $backdoor_preg_replace = /preg_replace\s*\(\s*['"][/e]['"]\s*,\s*[$_A-Z]+\['[A-Z_]+\']\s*,\s*[$_A-Z]+\['[A-Z_]+\']\s*\)/ nocase
        $backdoor_assert = /assert\s*\(\s*[$_A-Z]+\['[A-Z_]+\']\s*\)/ nocase
        $backdoor_call_user_func = /call_user_func\s*\(\s*[$_A-Z]+\['[A-Z_]+\']\s*\)/ nocase

    condition:
        any of them
}