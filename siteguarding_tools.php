<?php
/**
 * SiteGuarding tools installer for customer's panel
 *
 * https://www.siteguarding.com
 * Do not distribute or share.
 * 
 * ver.: 1.8
 * Date: 05 July 2022
 */
$allowed_IPs = array(
    '185.72.157.169',
    '185.72.157.170',
    '185.72.157.171',
    '185.72.157.172'
);

define('VERSION', '1.8');

define('DEBUG_MODE', false);

define('SITEGUARDING_SERVER', 'http://www.siteguarding.com/ext/panel_api/index.php');

$private_pgp_key = '-----BEGIN PRIVATE KEY-----
MIIBVwIBADANBgkqhkiG9w0BAQEFAASCAUEwggE9AgEAAkEApvw/ix3k2/D/yMlh
u9LhnpP6pna/91J+V4j0HeAiCmQu8wqnaQtXBUILUYk6jqu+KemuMNzocfA7rxEW
PWTCrQIDAQABAkEAhJu7prHlxlh7+KscZzlQHUvs+HdDeZhUZxWGr5cH0XF3eNoc
8tRF9kVoIwcAOcpM8s1ngkv83wQ9okD9tYxwjQIhANKzekmRpdp0dOxw+IctkWuG
h0hA5I5vUcbsM9Q86tzbAiEAyuLAtG17ucDJlj64eltAcyp2mSdS9xzG1h8zxSyf
MRcCIQCHtHUUoSwzMUKFbpWDawP4PyMulC0g1+3RsxwGnF2gdQIhAMkICf4+Bby3
JIg1OcIzrRbwWnfDGVg2MWd1n2yenFadAiEAzlDVVGN4Fn/0VM0pWD71hKw9TK3X
bS4xpkyQlDKC96c=
-----END PRIVATE KEY-----';


$scan_path = dirname(__FILE__);
if (!defined('DIRSEP'))
{
    if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') define('DIRSEP', '\\');
    else define('DIRSEP', '/');
}
define('WEBSITE_ROOT', dirname(__FILE__).DIRSEP);


// Init
date_default_timezone_set('Europe/London');
ignore_user_abort(true);
error_reporting( 0 );
ini_set('error_log',NULL);
ini_set('log_errors',0);
ini_set('max_execution_time',7200);
set_time_limit ( 7200 );
ini_set('memory_limit', '512M');


/**
 * Start
 */
$ip_address = $_SERVER["REMOTE_ADDR"];
if (isset($_SERVER["HTTP_X_REAL_IP"])) $ip_address = $_SERVER["HTTP_X_REAL_IP"];
if (isset($_SERVER["HTTP_X_FORWARDED_FOR"])) $ip_address = $_SERVER["HTTP_X_FORWARDED_FOR"];
if (isset($_SERVER["HTTP_CF_CONNECTING_IP"])) $ip_address = $_SERVER["HTTP_CF_CONNECTING_IP"];

if (DEBUG_MODE) SaveLog('Start session for '.$ip_address);
$task_id = '';
if (isset($_REQUEST['task_id'])) $task_id = trim($_REQUEST['task_id']);
if ($task_id == '' && isset($_POST['task_id'])) $task_id = trim($_POST['task_id']);
if ($task_id == '') die('siteguarding_tools.php is ok (ver. '.VERSION.')'.CheckError());


/**
 * Actions without authorization
 */

// Recovery action
if ($task_id == 'recovery')
{
    if (basename(dirname(__FILE__)) == 'webanalyze')
    {
        $restored_file = dirname(dirname(__FILE__)).DIRSEP.'siteguarding_tools.php';
        if (copy(__FILE__, $restored_file)) die('RESTORED_OK');
        else die('RESTORED_FAILED');
    }
    else die('RESTORE_IGNORED');
}


// Check if request came from allowed IP address
$is_allowed_session = false;
foreach ($allowed_IPs as $ip)
{
    if ($ip_address == trim($ip))
    {
        $is_allowed_session = true;
        break;
    }
}

if (DEBUG_MODE) SaveLog('Session is '.var_export($is_allowed_session, true));

// Check by host
if ($is_allowed_session === false)
{
    $host = gethostbyaddr($ip_address);
    if (stripos($host, "hosting") === false && substr($host, -16) == 'siteguarding.com') $is_allowed_session = true;
}

// Check by PGP
if ($is_allowed_session === false)
{
    // Check session with PGP way
    $task_pgp = '';
    if (isset($_REQUEST['task_pgp'])) $task_pgp = trim($_REQUEST['task_pgp']);
    if ($task_pgp == '' && isset($_POST['task_pgp'])) $task_pgp = trim($_POST['task_pgp']);
    if ($task_pgp == '') die('task_pgp error');
    
    $task_pgp = trim(PGP_decrypt($task_pgp, $private_pgp_key));
    if (DEBUG_MODE) SaveLog('$task_id='.$task_id.' , $task_pgp='.$task_pgp);
    if ($task_pgp != $task_id) die('task_pgp wrong value');
}


/**
 * Actions with authorization
 */

// Ping action
if ($task_id == 'ping')
{
    $a = array('status' => 'PING_OK', 'ver' => VERSION);
    $login = WEBSITE_ROOT.'webanalyze'.DIRSEP.'website-security-conf.php';
    if (file_exists($login))
    {
        $a['login'] = Read_File($login);
    }
    
    $backup_file = WEBSITE_ROOT.'webanalyze'.DIRSEP.'siteguarding_tools.php';
    if (!file_exists($backup_file) || filesize(__FILE__) > filesize($backup_file))
    {
        $folder_webanalyze = WEBSITE_ROOT.'webanalyze';
        if (!file_exists($folder_webanalyze)) mkdir($folder_webanalyze);
        copy(__FILE__, $backup_file);
    }
    
    die(json_encode($a));
}

// Manual Update
if ($task_id == 'update')
{
	if (ManualUpdate()) die('UPDATED');
	else die('UPDATE FAILED');   
}


// Connect to SiteGuarding.com server
$link = SITEGUARDING_SERVER.'?action=siteguarding_tools&task_id='.$task_id;
$task_json = trim(GetRemote_file_contents($link));
if ($task_json == '') die('Empty task_json');
$task_json = (array)json_decode($task_json, true);
if ( is_array($task_json) === false || $task_json === false) die('False decode task_json');

foreach ($task_json as $task_code => $task_data)
{
	if (DEBUG_MODE) SaveLog('task_code='.$task_code);
    switch ($task_code)
    {
        case 'savefile':
            Task_savefile($task_data);
            break;
            
        case 'showfile':
            Task_showfile($task_data);
            break;
            
        case 'deletefile':
            Task_deletefile($task_data);
            break;
            
        case 'copyfile':
            Task_copyfile($task_data);
            break;
            
        case 'download':
            Task_download($task_data);
            break;
            
        case 'includefile':
            Task_includefile($task_data);
            break;
            
        case 'fileinfo':
            Task_fileinfo($task_data);
            break;
    }
}

exit;





/**
 * functions
 */

function Task_deletefile($task_data)
{
    if (count($task_data))
    {
        foreach ($task_data as $data_row)
        {
            $filename = $data_row['file'];
            
            if (file_exists(WEBSITE_ROOT.$filename)) unlink(WEBSITE_ROOT.$filename);

        }
    }
}


function Task_copyfile($task_data)
{
    if (count($task_data))
    {
        foreach ($task_data as $data_row)
        {
            $filename = $data_row['file'];
            $filename_to = $data_row['file_to'];
            
            if (file_exists(WEBSITE_ROOT.$filename)) copy(WEBSITE_ROOT.$filename, WEBSITE_ROOT.$filename_to);
        }
    }
}


function Task_savefile($task_data)
{
    if (count($task_data))
    {
        foreach ($task_data as $data_row)
        {
            $filename = $data_row['file'];
            
            if ($filename == 'create_folder') 
            {
                $folder = WEBSITE_ROOT.$data_row['content'];
                if (!file_exists($folder)) mkdir($folder);
                continue;
            }
            
            $content = base64_decode($data_row['content']);
            
            if ($content !== false) 
            {
                if ( isset($data_row['skip']) && intval($data_row['skip']) == 1 )
                {
                    if (file_exists(WEBSITE_ROOT.$filename)) continue;
                }
                Save_File(WEBSITE_ROOT.$filename, $content);
            }
        }
    }
}


function Task_showfile($task_data)
{
    $a = array();
    if (count($task_data))
    {
        foreach ($task_data as $data_row)
        {
            $filename = $data_row['file'];
            if (isset($data_row['size']))
            {
                // Show by size
                if (filesize(WEBSITE_ROOT.$filename) == $data_row['size']) continue;
            }
            
            $a[$filename] = base64_encode(Read_File(WEBSITE_ROOT.$filename));
        }
    }
    
    if (count($a))
    {
        echo json_encode($a);
    }
}

function Task_download($task_data)
{
    $file = WEBSITE_ROOT.trim($task_data['file']);
    
    if (!is_file($file)) die('ERROR');
    
    //if (isset($task_data['size']) && intval($task_data['size']) > 0) $filesize = intval($task_data['size']);
    //else $filesize = filesize($file);
    
    if (isset($task_data['size']))
    {
        $size = intval($task_data['size']);
        if ($size >= 0) 
        {
            $filesize = $size;
            if ($size == 0) $content = @readfile($file);
            else {
                $fp = fopen($file, "r");
                $content = fread($fp, $size);
                fclose($fp);
            }
        }
        else {
            $filesize = abs($size);
            $fp = fopen($file, 'r');
            fseek($fp, $size, SEEK_END);
            $content = fgets($fp, $filesize);
        }
    }
    else $filesize = filesize($file);
    
    if (isset($task_data['lines']))
    {
        $lines = intval($task_data['lines']);
        
        $lines_data = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        
        if ($lines > 0) $content_arr = array_slice($lines_data, 0, $lines);
        else $content_arr = array_slice($lines_data, $lines);
        
        $content = implode("\n", $content_arr);
        $filesize = strlen($content);
    }
    
    header('Pragma: public');
    header('Expires: 0');
    header('Cache-Control: must-revalidate, post-check=0, pre-check=0');
    header('Cache-Control: private', false);
    header('Content-Transfer-Encoding: binary');
    header('Content-Disposition: attachment; filename="'.basename($file).'";');
    header('Content-Type: application/octet-stream');
    header('Content-Length: ' . $filesize);
    
    ob_clean();
    flush();
    echo $content;
    exit;
}


function Task_fileinfo($task_data)
{
    $a = array();
    if (count($task_data))
    {
        foreach ($task_data as $data_row)
        {
            $filename = $data_row['file'];
            if (is_file(WEBSITE_ROOT.$filename)) 
            {
                if (isset($data_row['md5']) && intval($data_row['md5']) == 1) $md5file = md5_file(WEBSITE_ROOT.$filename);
                else $md5file = '';
                
                $a[$filename] = array('exists' => 1, 'size' => filesize(WEBSITE_ROOT.$filename), 'time' => filectime(WEBSITE_ROOT.$filename), 'md5' => $md5file);
            }
            else $a[$filename] = array('exists' => 0);
        }
    }
    
    if (count($a))
    {
        echo json_encode($a);
    }
}



function Task_includefile($task_data)
{
	if (DEBUG_MODE) SaveLog('Task_infile start');
    $folder_webanalyze = WEBSITE_ROOT.'webanalyze';
    if (!file_exists($folder_webanalyze)) mkdir($folder_webanalyze);
    $include_file = $folder_webanalyze.DIRSEP.'tools_include_'.rand(0, 1000).'_'.rand(0, 1000).'.tmpcode';
	if (DEBUG_MODE) SaveLog('file='.$include_file);
    Save_File($include_file, $task_data['code']);
    include($include_file);
    unlink($include_file);
	if (DEBUG_MODE) SaveLog('Task_infile end');
}


function Save_File($file, $content)
{
    $fp = fopen($file, 'w');
    fwrite($fp, $content);
    fclose($fp);
}

function Read_File($file)
{
    $contents = '';
    
    if (file_exists($file))
    {
        $filesize = filesize($file);
        if ($filesize > 0)
        {
            $fp = fopen($file, "r");
            $contents = fread($fp, $filesize);
            fclose($fp); 
        }
    }
    
    return $contents;
}


function PGP_decrypt($data, $key){
	
	$data = base64_decode($data);
	$status = openssl_private_decrypt($data, $result, $key);
    if (DEBUG_MODE) SaveLog('PGP decrypt status: '.var_export($status, true));
    if ($status) return $result;
    else return false;
}



function ManualUpdate()
{
    $link = SITEGUARDING_SERVER.'?action=update';
    $data = (array)json_decode(trim(GetRemote_file_contents($link)), true);
    $content = base64_decode($data['b64content']);
    if (md5($content) == $data['md5'])
    {
        Save_File(__FILE__, $content);
        return true;
    }
    else return false;
}

function GetRemote_file_contents($url, $post_data = array(), $parse = false)
{
    if (extension_loaded('curl')) 
    {
        $ch = curl_init();
        
        $postvars = '';
        foreach($post_data as $key => $value) 
        {
            $postvars .= $key . "=" . $value . "&";
        }
        
        curl_setopt($ch, CURLOPT_URL, $url );
        curl_setopt($ch, CURLOPT_USERAGENT, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:38.0) Gecko/20100101 Firefox/38.0");
        curl_setopt($ch, CURLOPT_TIMEOUT, 3600);
        curl_setopt($ch, CURLOPT_TIMEOUT_MS, 3600000);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        
        if (count($post_data) > 0)
        {
            curl_setopt($ch,CURLOPT_POST, 1);
            curl_setopt($ch,CURLOPT_POSTFIELDS, $postvars);
        }

        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10); // 10 sec
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT_MS, 10000); // 10 sec
        curl_setopt($ch, CURLOPT_BINARYTRANSFER, 1);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        
        $output = curl_exec($ch);
		if ($output === false && DEBUG_MODE) SaveLog('ERROR cURL request: '.curl_error($ch));
		
		$output = trim($output);
		if (DEBUG_MODE) SaveLog('cURL output '.$output);
        curl_close($ch);
        
        if ($output === false || trim($output) == '')  return false;
        
        if ($parse === true) $output = (array)json_decode($output, true);
		
        return $output;
    }
    else {
		if (DEBUG_MODE) SaveLog('ERROR - cURL is not enabled');
		return false;
	}
}

function CreateRemote_file_contents($url, $dst)
{
    $a = CreateRemote_file_contents_ext($url, $dst);
    
    if ($a === false || $a == 0) 
    {
        if (stripos($url, "http://") !== false)
        {
            $url = str_replace("http://", "https://", $url);
            $a = CreateRemote_file_contents_ext($url, $dst);
        }
    }
    
    return $a;
}

function CreateRemote_file_contents_ext($url, $dst)
{
    if (extension_loaded('curl')) 
    {
        $dst = fopen($dst, 'w');
        
        $ch = curl_init();
        
        curl_setopt($ch, CURLOPT_URL, $url );
        curl_setopt($ch, CURLOPT_USERAGENT, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:38.0) Gecko/20100101 Firefox/38.0");
        curl_setopt($ch, CURLOPT_TIMEOUT, 3600);
        curl_setopt($ch, CURLOPT_TIMEOUT_MS, 3600000);
        curl_setopt($ch, CURLOPT_FILE, $dst);
        curl_setopt($ch, CURLOPT_FAILONERROR, true);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 30); // 30 sec
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT_MS, 30000); // 30 sec
        curl_setopt($ch, CURLOPT_BINARYTRANSFER, 1);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        
        $a = curl_exec($ch);
        if ($a === false)  return false;
        
        $info = curl_getinfo($ch);
        
        curl_close($ch);
        fflush($dst);
        fclose($dst);
        
        return $info['size_download'];
    }
    else return false;
}

function SaveLog($contents)
{
	$filename = dirname(__FILE__).'/siteguarding_tools.log';
    $fp = fopen($filename, 'a');
    fwrite($fp, date("Y-m-d H:i:s").' '.$contents."\n");
    fclose($fp);
}

function CheckError()
{
	$errors = array();
	
	if (!extension_loaded('curl')) $errors[] = 'cURL is not enabled';
	else {
		$num = rand(10, 10000);
		$link = SITEGUARDING_SERVER.'?action=ping_siteguarding_server&num='.$num;
		$answer = trim(GetRemote_file_contents($link));
		$answer = (array)json_decode($answer, true);
		
		if (isset($answer['status']) && trim($answer['status']) == 'ok' && intval($answer['num']) == $num)
		{
			
		}
		else $errors[] = 'Your server can not connect to siteguarding.com server using cURL. Contact your hosting support and ask them to add IP addresses: 185.72.157.169, 185.72.157.170 to allow list';
	}
	
	if (count($errors) > 0) return ' [Detected errors: '.implode(", ", $errors).']';
	else return '';
}
/*DONT REMOVE                                                      */
?>