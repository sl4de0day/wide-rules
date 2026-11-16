<?php
$cmd = $_GET['ip'];
system("ping -c 4 " . $cmd);

$id = $_POST['id'];
$res = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id);

$raw = $_COOKIE['session_payload'];
$obj = unserialize($raw);
?>
