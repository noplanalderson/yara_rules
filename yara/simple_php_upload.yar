rule Detect_Malicious_PHP_Uploader {
    meta:
        author = "Mr. Naeem"
        description = "Detects a malicious PHP uploader script"
        created = "2024-12-14"
        version = "1.0"

    strings:
        $php_tag = "<?php"
        $uploader_condition = "isset($_GET[\"uploader\"])"
        $php_uname = "php_uname()"
        $disable_functions = "ini_get(\"disable_functions\")"
        $file_upload = "multipart/form-data"
        $file_copy = "copy($_FILES"
        $upload_check = "if($_POST[\"k\"]==upload)"
        $success_msg = "echo\"<b>\".$_FILES[\"f\"][\"name\"]"

    condition:
        all of ($php_tag, $uploader_condition, $php_uname, $disable_functions, $file_upload, $file_copy, $upload_check, $success_msg)
}
