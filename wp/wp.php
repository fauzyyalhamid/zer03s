<?php
/*
------------------------------------------------------------------------------------------------------------
| WordPress Password Cracker v.1
| Released Date:11/01/2012
| autor	 : wordpress.org
| edited : tegex21 
| thanks : Yogyacarderlink | all indonesian Blackhat | security Blackhat team
------------------------------------------------------------------------------------------------------------
 */

$getClientIp= $_SERVER['REMOTE_ADDR'];

class PasswordHash {
	var $itoa64;
	var $iteration_count_log2;
	var $portable_hashes;
	var $random_state;

	function PasswordHash($iteration_count_log2, $portable_hashes)
	{
		$this->itoa64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

		if ($iteration_count_log2 < 4 || $iteration_count_log2 > 31)
			$iteration_count_log2 = 8;
		$this->iteration_count_log2 = $iteration_count_log2;

		$this->portable_hashes = $portable_hashes;

		$this->random_state = microtime() . uniqid(rand(), TRUE); // removed getmypid() for compability reasons
	}

	function get_random_bytes($count)
	{
		$output = '';
		if ( @is_readable('/dev/urandom') &&
		    ($fh = @fopen('/dev/urandom', 'rb'))) {
			$output = fread($fh, $count);
			fclose($fh);
		}

		if (strlen($output) < $count) {
			$output = '';
			for ($i = 0; $i < $count; $i += 16) {
				$this->random_state =
				    md5(microtime() . $this->random_state);
				$output .=
				    pack('H*', md5($this->random_state));
			}
			$output = substr($output, 0, $count);
		}

		return $output;
	}

	function encode64($input, $count)
	{
		$output = '';
		$i = 0;
		do {
			$value = ord($input[$i++]);
			$output .= $this->itoa64[$value & 0x3f];
			if ($i < $count)
				$value |= ord($input[$i]) << 8;
			$output .= $this->itoa64[($value >> 6) & 0x3f];
			if ($i++ >= $count)
				break;
			if ($i < $count)
				$value |= ord($input[$i]) << 16;
			$output .= $this->itoa64[($value >> 12) & 0x3f];
			if ($i++ >= $count)
				break;
			$output .= $this->itoa64[($value >> 18) & 0x3f];
		} while ($i < $count);

		return $output;
	}

	function gensalt_private($input)
	{
		$output = '$P$';
		$output .= $this->itoa64[min($this->iteration_count_log2 +
			((PHP_VERSION >= '5') ? 5 : 3), 30)];
		$output .= $this->encode64($input, 6);

		return $output;
	}

	function crypt_private($password, $setting)
	{
		$output = '*0';
		if (substr($setting, 0, 2) == $output)
			$output = '*1';

		$id = substr($setting, 0, 3);
		# We use "$P$", phpBB3 uses "$H$" for the same thing
		if ($id != '$P$' && $id != '$H$')
			return $output;

		$count_log2 = strpos($this->itoa64, $setting[3]);
		if ($count_log2 < 7 || $count_log2 > 30)
			return $output;

		$count = 1 << $count_log2;

		$salt = substr($setting, 4, 8);
		if (strlen($salt) != 8)
			return $output;

		# We're kind of forced to use MD5 here since it's the only
		# cryptographic primitive available in all versions of PHP
		# currently in use.  To implement our own low-level crypto
		# in PHP would result in much worse performance and
		# consequently in lower iteration counts and hashes that are
		# quicker to crack (by non-PHP code).
		if (PHP_VERSION >= '5') {
			$hash = md5($salt . $password, TRUE);
			do {
				$hash = md5($hash . $password, TRUE);
			} while (--$count);
		} else {
			$hash = pack('H*', md5($salt . $password));
			do {
				$hash = pack('H*', md5($hash . $password));
			} while (--$count);
		}

		$output = substr($setting, 0, 12);
		$output .= $this->encode64($hash, 16);

		return $output;
	}

	function gensalt_extended($input)
	{
		$count_log2 = min($this->iteration_count_log2 + 8, 24);
		# This should be odd to not reveal weak DES keys, and the
		# maximum valid value is (2**24 - 1) which is odd anyway.
		$count = (1 << $count_log2) - 1;

		$output = '_';
		$output .= $this->itoa64[$count & 0x3f];
		$output .= $this->itoa64[($count >> 6) & 0x3f];
		$output .= $this->itoa64[($count >> 12) & 0x3f];
		$output .= $this->itoa64[($count >> 18) & 0x3f];

		$output .= $this->encode64($input, 3);

		return $output;
	}

	function gensalt_blowfish($input)
	{
		# This one needs to use a different order of characters and a
		# different encoding scheme from the one in encode64() above.
		# We care because the last character in our encoded string will
		# only represent 2 bits.  While two known implementations of
		# bcrypt will happily accept and correct a salt string which
		# has the 4 unused bits set to non-zero, we do not want to take
		# chances and we also do not want to waste an additional byte
		# of entropy.
		$itoa64 = './ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

		$output = '$2a$';
		$output .= chr(ord('0') + $this->iteration_count_log2 / 10);
		$output .= chr(ord('0') + $this->iteration_count_log2 % 10);
		$output .= '$';

		$i = 0;
		do {
			$c1 = ord($input[$i++]);
			$output .= $itoa64[$c1 >> 2];
			$c1 = ($c1 & 0x03) << 4;
			if ($i >= 16) {
				$output .= $itoa64[$c1];
				break;
			}

			$c2 = ord($input[$i++]);
			$c1 |= $c2 >> 4;
			$output .= $itoa64[$c1];
			$c1 = ($c2 & 0x0f) << 2;

			$c2 = ord($input[$i++]);
			$c1 |= $c2 >> 6;
			$output .= $itoa64[$c1];
			$output .= $itoa64[$c2 & 0x3f];
		} while (1);

		return $output;
	}

	function HashPassword($password)
	{
		$random = '';

		if (CRYPT_BLOWFISH == 1 && !$this->portable_hashes) {
			$random = $this->get_random_bytes(16);
			$hash =
			    crypt($password, $this->gensalt_blowfish($random));
			if (strlen($hash) == 60)
				return $hash;
		}

		if (CRYPT_EXT_DES == 1 && !$this->portable_hashes) {
			if (strlen($random) < 3)
				$random = $this->get_random_bytes(3);
			$hash =
			    crypt($password, $this->gensalt_extended($random));
			if (strlen($hash) == 20)
				return $hash;
		}

		if (strlen($random) < 6)
			$random = $this->get_random_bytes(6);
		$hash =
		    $this->crypt_private($password,
		    $this->gensalt_private($random));
		if (strlen($hash) == 34)
			return $hash;

		# Returning '*' on error is safe here, but would _not_ be safe
		# in a crypt(3)-like function used _both_ for generating new
		# hashes and for validating passwords against existing hashes.
		return '*';
	}

	function CheckPassword($password, $stored_hash)
	{
		$hash = $this->crypt_private($password, $stored_hash);
		if ($hash[0] == '*')
			$hash = crypt($password, $stored_hash);

		return $hash == $stored_hash;
	}
}

if(!empty($_POST['hash']) && !empty($_POST['list'])){
set_time_limit(9000);
 
$wp_hasher = new PasswordHash(8, TRUE);
 
$password_hashed = $_POST['hash'];
$wordlist = $_POST['list'];


if(file_exists($wordlist)){
$file = fopen($wordlist, 'r');
while(!feof($file)) {
$word = fgets($file, 4096);

if($wp_hasher->CheckPassword(rtrim($word), $password_hashed) || $password_hashed == md5(rtrim($word))) {
		$return = 'Password Cracked !<br><font color=#33FF00 size=3>hashes found <br> 
'.$password_hashed.' :<blink><b> '.$word.'</b></blink></font>';
		$cracked = true;
	}
}
if($cracked == false) {
$return = '<font color=red size=3><br><br>i am sorry friend .. ! hashes Not Found. </font>';
}
fclose($file);
}else{
$return = '<font color=white size=2><br><br>Word List File Not Found. </font>';
}
}
?>
<center>
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta content="text/html; charset=utf-8" http-equiv="Content-Type" />
<title>Wordpress cracker  V.1</title>
<style type="text/css">
*,html,body,div,p,h2{
padding: 0px;margin: 0px;}
body{background-color: black; font-color:0033FF;}
#container{margin: 0 auto;width: 980px;padding-top: 40px;}
#content-container{float: left;width: 980px;}
#content{clear: left;float: left;width: 581px;padding: 20px 0 20px 0;margin: 0 0 0 30px;display: inline;color: #333;}
#content h2 {font-family: tahoma;font-size: 170px;}
#aside{float: right;width: 348px;padding: 0px;display: inline;background-image: url('http://cy63r.persiangig.com/image/805740121.jpg');height: 376px;}.
hacker{float: right;font-family: Cambria;font-size: 30px;font-weight: bold;}
.notes{padding-top: 90px;line-height: 1.3em;font-weight: bold;font-size: 16px;font-family: "Courier New";}
.contact{padding-top: 30px;font-size: 18px;font-family: "Courier New", Courier, monospace;font-weight: bold;color: #800000;}
#music{padding: 80px 80px 0px 0px;float: right;clear: right;}
</style>
</head>
<style type = "text/css">
    A:link {color: #33FF00; text-decoration: none}
    A:visited {color: #33FF00; text-decoration: none}
    A:active {text-decoration: none}

.iamine{
border: 1px #33FF00 solid;
background:#000000;
color:#FFFFFF;
}
.i{
width: 100px;
border: 1px #33FF00 solid;
background:#000000;
color:#FFFFFF;
}
.z{
width: 130px;
font-size: 12px;
border: 1px #33FF00 solid;
background:#000000;
color:#FFFFFF;
}
</style>

<title>WordPress Password Cracker</title>
<form method="post" action=""><br><br><br><br><br><br>
<h1><font color="#33FF00"> WordPress Password Cracker </font></h1>

<br>
<table style = "border: 1px #000000 solid;">
<tr>
	<td class="z"><font color=black>..</font>your IP</td>
        <td class="z"><? print $getClientIp ?></td>
</tr>
	<tr>
		<td class="z"><font color=black>..</font>MD5(wordpress)</td>
                <td>
<input type="text" class = "iamine" name="hash" size="60" value="<? print($_POST['hash']); ?>"/></td>
	</tr>
	<tr>
		<td class="z"><font color=black>..</font>List of Word:</td>
                <td>

<input type="txt" class = "iamine" name="list" value="wordlist.txt" size="60"/>
		
				</td>
	</tr>
</table>
<br>
<input type="submit" name="login" value="Crack" class="i"/></form>
<br>
<?
echo $return;
?>

<br><br><br><br><br><br><br><br><br><br><hr color='#33FF00' width='500px' height: 2px/>
<font color="#33FF00" size=3>wordpress.org &copy; 2012 & modified: ./tegex21<br>
<a href="http://www.yogyacarderlink.web.id" target=" _blank"> Yogycarderlink | Indonesian Blackhat Team</font></a>

</center>
</html>