<?php
# 
# https://dyndns.example.com/update.php?usr=<username>&pwd=<pass>&domain=<domain>&ipaddr=<ipaddr>&ip6addr=<ip6addr>&ip6lanprefix=<ip6lanprefix> 
# 

header("Content-Type: text/plain");

// include configuration
require_once("./config.php");

// Connect to database
$DbConn = new mysqli(SQL_HOST, SQL_USERNAME, SQL_PASSWORD, SQL_DATABASE);

// Check connection
if ($DbConn->connect_error) {
    die("Connection failed: " . $DbConn->connect_error);
}

// Check for required arguments
if (empty($_REQUEST['usr']) || empty($_REQUEST['pwd']) || empty($_REQUEST['domain'])) {
	header($_SERVER["SERVER_PROTOCOL"]." 400 Bad Request");
	header("Status: 400 Bad Request");
	die("Invalid request (badagent)!\n");
}

##########################################
# Login
##########################################
$DbLoginStmt = $DbConn->prepare("select id, username, password, active from " . SQL_TABLEPREFIX . "users where username = ?");
$DbLoginStmt->bind_param("s", $_REQUEST['usr']);

$DbLoginStmt->execute();
$DbLoginStmt->bind_result($UserId, $UserName, $UserPassword, $UserActive);

// Verify login
if (!$DbLoginStmt->fetch()) {
	header($_SERVER["SERVER_PROTOCOL"]." 401 Unauthorized");
	header("Status: 401 Unauthorized");
	die("Invalid username (badauth)!\n");
}
if (!$UserActive) {
	header($_SERVER["SERVER_PROTOCOL"]." 401 Unauthorized");
	header("Status: 401 Unauthorized");
	die("User is inactive (badauth)!\n");
}
if (!password_verify($_REQUEST['pwd'], $UserPassword)) {
	header($_SERVER["SERVER_PROTOCOL"]." 401 Unauthorized");
	header("Status: 401 Unauthorized");
	die("Invalid password (badauth)!\n");
}

$DbLoginStmt->close();

##########################################
# Prepare updates
##########################################

$Updates = array();

##########################################
# Update domains (IPv6 prefix)
##########################################

# Helper
function textHexASCII($text){
	$bin = array();
    for($i=0; strlen($text)>$i; $i++)
    	$bin[] = dechex(ord($text[$i]));
    return implode(' ',$bin);
}

function ASCIIHexText($bin){
	$text = array();
	$bin = explode(" ", $bin);
	for($i=0; count($bin)>$i; $i++)
		$text[] = chr(hexdec($bin[$i]));
		
	return implode($text);
}

if ($_REQUEST['ip6lanprefix'] && (list($IPv6Prefix, $IPv6PrefixLength) = explode("/", $_REQUEST['ip6lanprefix']))) {
	// Read AAAA records for domain
	$DbDomainsStmt = $DbConn->prepare("SELECT records.id, records.name, records.content, dyndomains.prefix_length FROM records inner join " . SQL_TABLEPREFIX . "domains as dyndomains on records.domain_id = dyndomains.domain_id left join " . SQL_TABLEPREFIX . "users on dyndomains.user_id = " . SQL_TABLEPREFIX . "users.id where records.type = 'AAAA' and " . SQL_TABLEPREFIX . "users.id = ?");
	$DbDomainsStmt->bind_param("i", $UserId);
	$DbDomainsStmt->execute();
	$DbDomainsStmt->bind_result($RecordId, $RecordName, $RecordContent, $PrefixLength);

	// Override IPv6 LAN prefix if defined in dyndomains.prefix_length
	if (is_numeric($PrefixLength)) {
		$IPv6Prefix = $PrefixLength;
	}
	$IPv6PrefixBinary = inet_pton($IPv6Prefix);

	// Build mask
	$Byte = "";
	for ($i = 1; $i <= 128; $i++) {
		$Byte .= ($i<=$IPv6PrefixLength ? "1" : "0");
		if ($i%8 == 0) {
			$Bytes[] = chr(bindec($Byte));
			$Byte = "";
		}
	}
	$IPv6MaskBinary = implode($Bytes);

	// Update Prefix in AAAA records
	while ($DbDomainsStmt->fetch()) {
		$IPv6AdressBinary = inet_pton($RecordContent);
		$IPv6Adress = inet_ntop(($IPv6AdressBinary & (~ $IPv6MaskBinary)) | ($IPv6PrefixBinary & $IPv6MaskBinary));

		// update record only if the new IPv6 address is valid
		if (filter_var($IPv6Adress, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
			$Updates[$RecordId] = $IPv6Adress;
		}
	}
	$DbDomainsStmt->close();
}

##########################################
# Update Record (IPv4 and IPv6)
##########################################

// Read A and AAAA records
$DbRecordsStmt = $DbConn->prepare("SELECT records.id, records.name, records.type, records.content FROM records inner join " . SQL_TABLEPREFIX . "records on records.id = " . SQL_TABLEPREFIX . "records.record_id left join " . SQL_TABLEPREFIX . "users on " . SQL_TABLEPREFIX . "records.user_id = " . SQL_TABLEPREFIX . "users.id where records.type IN ('A','AAAA') and " . SQL_TABLEPREFIX . "users.id = ?");

$DbRecordsStmt->bind_param("i", $UserId);
$DbRecordsStmt->execute();
$DbRecordsStmt->bind_result($RecordId, $RecordName, $RecordType, $RecordContent);

// Update Prefix in A and AAAA records
while ($DbRecordsStmt->fetch()) {
	switch ($RecordType) {
		case "A":
			// update record only if the new IPv4 address is valid
			if (isset($_REQUEST['ipaddr']) && filter_var($_REQUEST['ipaddr'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
				$Updates[$RecordId] = $_REQUEST['ipaddr'];
			}
			break;
		case "AAAA":
			// update record only if the new IPv6 address is valid
			if (isset($_REQUEST['ip6addr']) && filter_var($_REQUEST['ip6addr'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
				$Updates[$RecordId] = $_REQUEST['ip6addr'];
			} else {
				// Do not update records that should have a IPv6 address outside the lan prefix
				unset($Updates[$RecordId]);
			}
			break;
	}
}

$DbRecordsStmt->close();

##########################################
# Write updated records into database
##########################################

$DbUpdateStmt = $DbConn->prepare("update records set content = ? where id = ?");

$RecordContent = "";
$RecordId = 0;
$DbUpdateStmt->bind_param("si", $RecordContent, $RecordId);

foreach ($Updates as $RecordId => $RecordContent) {
	$DbUpdateStmt->execute();
}

$DbUpdateStmt->close();

// Log request
if (LOG_LAST_REQUEST) {
	file_put_contents("./REQUEST.txt", print_r($_REQUEST, true));
}

print_r($Updates);

# Disconnect from database
$DbConn->close();

die("Completed");
#############################################



// Print result
print($result);

# Log result
if ($LOG_LAST_RESULT) {
	file_put_contents("./RESULT.txt", $result);
}
