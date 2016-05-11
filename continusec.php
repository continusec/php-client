<?php

/*
   Copyright 2016 Continusec Pty Ltd

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

error_reporting(-1);

$NORMALIZE_FUNC = function ($o) { return $o; };
if (function_exists("normalizer_normalize")) {
	$NORMALIZE_FUNC = function($o) { return normalizer_normalize($o, Normalizer::FORM_C); };
} else {
	error_log("WARNING: normalizer_normalize (part of php-intl package) is required for proper unicode normalization for objecthash. Proceeding without, so non-ASCII characters may not verify correctly.", 0);
}

if (!function_exists("curl_init")) {
	error_log("ERROR: curl_init not found. Without this the Continusec library can't make outbound connections.", 0);
}


$REDACTED_PREFIX = "***REDACTED*** Hash: ";

/* PHP doesn't distinguish between a list and a map - sigh, so here is our best attempt */
function is_array_a_list($o, $def) {
	$keys = array_keys($o);
	if (count($keys) == 0) {
		return $def; /* ambiguous, caller gives us best guess */
	} else {
		return $keys === range(0, count($o)-1);
	}
}

function object_hash_list_with_redaction($o, $r) {
	$rv = "l";
	for ($i = 0; $i < count($o); $i++) {
		$rv .= object_hash_with_redaction($o[$i], $r);
	}
	return hash("sha256", $rv, true);
}

function object_hash_map_with_redaction($o, $r) {
	$keys = array_keys($o);
	$kvs = array();
	for ($i = 0; $i < count($keys); $i++) {
		array_push($kvs, object_hash_with_redaction($keys[$i], $r).object_hash_with_redaction($o[$keys[$i]], $r));
	}
	sort($kvs);
	return hash("sha256", "d".join("", $kvs), true);
}

function object_hash_float($o) {
	$s = "+";
	if ($o < 0) {
		$s = "-";
		$o = -$o;
	}
	$e = 0;
	while ($o > 1) {
		$o /= 2.0;
		$e++;
	}
	while ($o <= 0.5) {
		$o *= 2.0;
		$e--;
	}
	$s .= $e.":";
	if (($o > 1) || ($o <= 0.5)) {
		throw new Exception("Error normalizing float (1)");
	}
	while ($o != 0) {
		if ($o >= 1) {
			$s .= "1";
			$o -= 1.0;
		} else {
			$s .= "0";
		}
		if ($o >= 1) {
			throw new Exception("Error normalizing float (2)");
		}
		if (strlen($s) >= 1000) {
			throw new Exception("Error normalizing float (3)");
		}
		$o *= 2.0;
	}
	return hash("sha256", "f".$s, true);
}

function object_hash_with_redaction($o, $r) {
	global $NORMALIZE_FUNC;
	switch (gettype($o)) {
	case "boolean":
		if ($o) {
			return hash("sha256", "b1", true);
		} else {
			return hash("sha256", "b0", true);
		}
	case "integer": // for now, treat all integers as floats since JSON does not distinguish
	case "double":
		return object_hash_float($o);
	case "string":
		if ((strlen($r) > 0) && (0 === strpos($o, $r))) {
			return hex2bin(substr($o, strlen($r)));
		} else {
			return hash("sha256", "u".$NORMALIZE_FUNC($o), true);
		}
	case "array":
		if (is_array_a_list($o, true)) {
			return object_hash_list_with_redaction($o, $r);
		} else {
			return object_hash_map_with_redaction($o, $r);
		}
	case "object": // we are relying on json parser using objects, not associative arrays.
		// otherwise we are unable to distinguish [] from {}.
		return object_hash_map_with_redaction(get_object_vars($o), $r);
	case "resource":
		throw new Exception("Type resource not supported for objecthash");
	case "NULL":
		return hash("sha256", "n", true);
	default:
		throw new Exception("Type unknown not supported for objecthash");
	}
}

function object_hash($o) {
	return object_hash_with_redaction($o, "");
}

function object_hash_with_std_redaction($o) {
	global $REDACTED_PREFIX;
	return object_hash_with_redaction($o, $REDACTED_PREFIX);
}

function shed_std_redactibility($o) {
	global $REDACTED_PREFIX;
	return shed_redactibility($o, $REDACTED_PREFIX);
}

function unredact_dict($o, $r) {
	$rv = new stdClass();
	$keys = array_keys($o);
	for ($i = 0; $i < count($o); $i++) {
		$k = $keys[$i];
		$v = $o[$k];
		switch (gettype($v)) {
		case "array":
			if (count($v) == 2) {
				$rv->$k = shed_redactibility($v[1], $r);
				break;
			} else {
				throw new Exception("Unrecognized value in object that we expected to be redacted (3)");
			}
		case "string":
			if ((strlen($r) > 0) && (0 === strpos($v, $r))) {
				// all good, but do nothing
				break;
			} else {
				throw new Exception("Unrecognized value in object that we expected to be redacted (1)");
			}
		default:
			throw new Exception("Unrecognized value in object that we expected to be redacted (2)");
		}
	}
	return $rv;
}

function unredact_list($o, $r) {
	$rv = array();
	for ($i = 0; $i < count($o); $i++) {
		array_push($rv, shed_redactibility($o[$i], $r));
	}
	return $rv;
}

function shed_redactibility($o, $r) {
	switch (gettype($o)) {
	case "array":
		if (is_array_a_list($o, true)) {
			return unredact_list($o, $r);
		} else {
			return unredact_dict($o, $r);
		}
		// deliberately fall through here
	case "object": // we are relying on json parser using objects, not associative arrays.
		// otherwise we are unable to distinguish [] from {}.
		return unredact_dict(get_object_vars($o), $r);
	default:
		return $o;
	}
}

class ContinusecClient {
	private $account;
	private $apiKey;
	private $baseUrl;

	function ContinusecClient($account, $apiKey, $baseUrl="https://api.continusec.com") {
		$this->account = $account;
		$this->apiKey = $apiKey;
		$this->baseUrl = $baseUrl;
	}

	public function getVerifiableLog($name) {
		return new VerifiableLog($this, "/log/".$name);
	}

	public function getVerifiableMap($name) {
		return new VerifiableMap($this, "/map/".$name);
	}

	/* not really intended to be public, just for internal use by this package */
	public function makeRequest($method, $path, $data) {
		$conn = curl_init();
		curl_setopt($conn, CURLOPT_URL, $this->baseUrl . "/v1/account/" . $this->account . $path);
		curl_setopt($conn, CURLOPT_HTTPHEADER, array("Authorization: Key " . $this->apiKey));

		curl_setopt($conn, CURLOPT_CUSTOMREQUEST, $method);
		curl_setopt($conn, CURLOPT_POSTFIELDS, $data);

		curl_setopt($conn, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($conn, CURLOPT_HEADER, true);

		$resp = curl_exec($conn);

		/* is there **really** no better way than this? :( */
		/* let's hope that chunked encoding won't break it */
		$headerSize = curl_getinfo($conn, CURLINFO_HEADER_SIZE);
		$header = substr($resp, 0, $headerSize);
		$resp = substr($resp, $headerSize);

		$statusCode = curl_getinfo($conn, CURLINFO_HTTP_CODE);
		curl_close($conn);

		if ($statusCode == 200) {
			return array(
				"headers"=>$header,
				"body"=>$resp
			);
		} else if ($statusCode == 400) {
			throw new Exception("Invalid request");
		} else if ($statusCode == 403) {
			throw new Exception("Unauthorized access");
		} else if ($statusCode == 404) {
			throw new Exception("Resource not found");
		} else {
			throw new Exception("Unknown error");
		}
	}
}

class VerifiableMap {
	private $client;
	private $path;

	function VerifiableMap($client, $path) {
		$this->client = $client;
		$this->path = $path;
	}

	function create() {
		$this->client->makeRequest("PUT", $this->path, null);
	}

	function getMutationLog() {
		return new VerifiableLog($this->client, $this.path."/log/mutation");
	}

	function getTreeHeadLog() {
		return new VerifiableLog($this->client, $this.path."/log/treehead");
	}

	function set($key, $value) {
		$this->client->makeRequest("PUT", $this->path . "/key/h/" . bin2hex($key), $value);
	}

	function setJson($key, $value) {
		$this->client->makeRequest("PUT", $this->path . "/key/h/" . bin2hex($key) . "/xjson", $value);
	}

	function setRedactibleJson($key, $value) {
		$this->client->makeRequest("PUT", $this->path . "/key/h/" . bin2hex($key) . "/xjson/redactible", $value);
	}

	function delete($key) {
		$this->client->makeRequest("DELETE", $this->path . "/key/h/" . bin2hex($key), null);
	}

	function internalGet($key, $treeSize, $format) {
		$rv = $this->client->makeRequest("GET", $this->path . "/tree/" . $treeSize . "/key/h/" . bin2hex($key) . $format, null);

	    $auditPath = array_fill(0, 256, null);
	    $lwrHdr = strtolower($rv["headers"]);

	    /* Sigh... surely PHP has a built-in header parser?? */
	    $pos = strpos($lwrHdr, "\r\nx-verified-proof:", 0);
	    while ($pos !== false) {
	        $end = strpos($lwrHdr, "\r\n", $pos + 19);
	        $part = trim(substr($lwrHdr, $pos + 19, $end - ($pos + 19)));
	        $slash = strpos($part, "/");
	        $auditPath[intval(substr($part, 0, $slash))] = hex2bin(substr($part, $slash + 1));
	        $pos = strpos($lwrHdr, "\r\nx-verified-proof:", $end);
	    }

	    return (object)[
	        "key"=>$key,
	        "value"=>$rv["body"],
	        "audit_path"=>$auditPath
	    ];
	}

	function get($key, $treeSize) {
		$rv = $this->internalGet($key, $treeSize, "");
		$rv->format = "raw";
		return $rv;
	}

	function getJson($key, $treeSize) {
		$rv = $this->internalGet($key, $treeSize, "/xjson");
		$rv->format = "xjson";
		$rv->rawJson = $rv->value;
		$rv->json = json_decode($rv->rawJson);
		$rv->value = object_hash_with_std_redaction($rv->json);
		return $rv;
	}

	function getRedactedJson($key, $treeSize) {
		$rv = $this->getJson($key, $treeSize);
		$rv->json = shed_std_redactibility($rv->json);
		return $rv;
	}

	function getTreeHash($treeSize=0) {
		$obj = json_decode($this->client->makeRequest("GET", $this->path . "/tree/" . $treeSize, null)["body"]);
		return (object)[
		    "tree_size"=>$obj->mutation_log->tree_size,
		    "root_hash"=>base64_decode($obj->map_hash)
		];
	}
}

class VerifiableLog {
	private $client;
	private $path;

	function VerifiableLog($client, $path) {
		$this->client = $client;
		$this->path = $path;
	}

	function create() {
		$this->client->makeRequest("PUT", $this->path, null);
	}

	function getTreeHash($treeSize=0) {
		$obj = json_decode($this->client->makeRequest("GET", $this->path . "/tree/" . $treeSize, null)["body"]);
		return (object)[
		    "tree_size"=>$obj->tree_size,
		    "root_hash"=>base64_decode($obj->tree_hash)
		];
	}

	function getInclusionProof($treeSize, $leafHash) {
		$obj = json_decode($this->client->makeRequest("GET", $this->path . "/tree/" . $treeSize . "/inclusion/h/" . bin2hex($leafHash), null)["body"]);
		$auditPath = array();
		foreach ($obj->proof as $p) {
		    array_push($auditPath, base64_decode($p));
		}
		return (object)[
		    "leaf_index"=>$obj->leaf_index,
		    "audit_path"=>$auditPath,
		    "leaf_hash"=>$leafHash
		];
	}

	function getConsistencyProof($firstSize, $secondSize) {
		$obj = json_decode($this->client->makeRequest("GET", $this->path . "/tree/" . $secondSize . "/consistency/" . $firstSize, null)["body"]);
		$auditPath = array();
		foreach ($obj->proof as $p) {
		    array_push($auditPath, base64_decode($p));
		}
		return $auditPath;
	}

	function addEntry($data) {
		$obj = json_decode($this->client->makeRequest("POST", $this->path . "/entry", $data)["body"]);
		return base64_decode($obj->leaf_hash);
	}

	function addJsonEntry($data) {
		$obj = json_decode($this->client->makeRequest("POST", $this->path . "/entry/xjson", $data)["body"]);
		return base64_decode($obj->leaf_hash);
	}

	function addRedactibleJsonEntry($data) {
		$obj = json_decode($this->client->makeRequest("POST", $this->path . "/entry/xjson/redactible", $data)["body"]);
		return base64_decode($obj->leaf_hash);
	}

	function internalGetEntry($idx, $format) {
		return $this->client->makeRequest("GET", $this->path . "/entry/" . $idx . $format, null)["body"];
	}

	function getEntry($idx) {
		return $this->internalGetEntry($idx, "");
	}

	function getJsonEntry($idx) {
		return decode_json($this->internalGetEntry($idx, "/xjson"));
	}

	function getRedactibleJsonEntry($idx) {
		return shed_std_redactibility(decode_json($this->internalGetEntry($idx, "/xjson")));
	}

	function getEntries($startIdx, $endIdx) {
	    $rv = array();
		foreach (json_decode($this->client->makeRequest("GET", $this->path . "/entries/" . $startIdx . "-" . $endIdx, null)["body"])->entries as $a) {
		    array_push($rv, base64_decode($a->leaf_data));
		}
		return $rv;
	}

	function getJsonEntries($startIdx, $endIdx) {
	    $rv = array();
		foreach (json_decode($this->client->makeRequest("GET", $this->path . "/entries/" . $startIdx . "-" . $endIdx, null)["body"])->entries as $a) {
		    array_push($rv, decode_json(base64_decode($a->leaf_data)));
		}
		return $rv;
	}

	function getRedactibleJsonEntries($startIdx, $endIdx) {
	    $rv = array();
		foreach (json_decode($this->client->makeRequest("GET", $this->path . "/entries/" . $startIdx . "-" . $endIdx, null)["body"])->entries as $a) {
		    array_push($rv, shed_std_redactibility(decode_json(base64_decode($a->leaf_data))));
		}
		return $rv;
	}
}

function leaf_merkle_tree_hash($b) {
    return hash("sha256", chr(0) . $b, true);
}

function node_merkle_tree_hash($l, $r) {
    return hash("sha256", chr(1) . $l . $r, true);
}

function verify_log_inclusion_proof($treeHash, $inclusionProof) {
    if (($inclusionProof->leaf_index >= $treeHash->tree_size) || ($inclusionProof->leaf_index < 0)) {
        throw new Exception("Invalid proof (1)");
    }

    $fn = intval($inclusionProof->leaf_index);
    $sn = intval($treeHash->tree_size) - 1;
    $r = $inclusionProof->leaf_hash;

    foreach($inclusionProof->audit_path as $p) {
        if (($fn == $sn) || (($fn & 1) == 1)) {
            $r = node_merkle_tree_hash($p, $r);
            while (!(($fn == 0) || (($fn & 1) == 1))) {
                $fn >>= 1;
                $sn >>= 1;
            }
        } else {
            $r = node_merkle_tree_hash($r, $p);
        }
        $fn >>= 1;
        $sn >>= 1;
    }

    if ($sn != 0) {
        throw new Exception("Invalid proof (2)");
    }

    if ($r != $treeHash->root_hash) {
        throw new Exception("Invalid proof (3)");
    }
}

function calc_k($n) {
    $k = 1;
    while (($k << 1) < $n) {
        $k <<= 1;
    }
    return $k;
}

function is_pow_2($n) {
    return calc_k($n + 1) == $n;
}

function verify_log_consistency_proof($firstTreeHead, $secondTreeHead, $proof) {
    if (($firstTreeHead->tree_size < 1) || ($firstTreeHead->tree_size >= $secondTreeHead->tree_size)) {
        throw new Exception("Invalid proof (4)");
    }

    if (is_pow_2($firstTreeHead->tree_size)) {
        array_unshift($proof, $firstTreeHead->root_hash);
    }

    $fn = $firstTreeHead->tree_size - 1;
    $sn = $secondTreeHead->tree_size - 1;

    while (($fn & 1) == 1) {
        $fn >>= 1;
        $sn >>= 1;
    }

    if (count($proof) == 0) {
        throw new Exception("Invalid proof (5)");
    }

    $fr = $proof[0];
    $sr = $proof[0];

    for ($i = 1; $i < count($proof); $i++) {
        if ($sn == 0) {
            throw new Exception("Invalid proof (6)");
        }

        if ((($fn & 1) == 1) || ($fn == $sn)) {
            $fr = node_merkle_tree_hash($proof[$i], $fr);
            $sr = node_merkle_tree_hash($proof[$i], $sr);
            while (!(($fn == 0) || (($fn & 1) == 1))) {
                $fn >>= 1;
                $sn >>= 1;
            }
        } else {
            $sr = node_merkle_tree_hash($sr, $proof[$i]);
        }

        $fn >>= 1;
        $sn >>= 1;
    }

    if ($sn != 0) {
        throw new Exception("Invalid proof (7)");
    }

    if ($fr != $firstTreeHead->root_hash) {
        throw new Exception("Invalid proof (8)");
    }

    if ($sr != $secondTreeHead->root_hash) {
        throw new Exception("Invalid proof (9)");
    }
}

function construct_map_key_path($key) {
    $h = hash("sha256", $key, true);
    $rv = array_fill(0, 256, false);
    for ($i = 0; $i < 32; $i++) {
        $b = ord($h[$i]);
        for ($j = 0; $j < 8; $j++) {
            if ((($b>>$j)&1)==1) {
                $rv[($i<<3)+7-$j] = true;
            }
        }
    }
    return $rv;
}

function verify_map_inclusion_proof($head, $value) {
    global $DEFAULT_LEAF_VALUES;

    $kp = construct_map_key_path($value->key);
    $t = leaf_merkle_tree_hash($value->value);
    for ($i = 255; $i >= 0; $i--) {
        $p = $value->audit_path[$i];
        if ($p == null) {
            $p = $DEFAULT_LEAF_VALUES[$i+1];
        }
        if ($kp[$i]) {
            $t = node_merkle_tree_hash($p, $t);
        } else {
            $t = node_merkle_tree_hash($t, $p);
        }
    }

    if ($t != $head->root_hash) {
        throw new Exception("Invalid proof (10)");
    }
}

function generate_map_default_leaf_values() {
    $rv = array_fill(0, 257, null);
    $rv[256] = leaf_merkle_tree_hash("");
    for ($i = 255; $i >= 0; $i--) {
        $rv[$i] = node_merkle_tree_hash($rv[$i+1], $rv[$i+1]);
    }
    return $rv;
}

$DEFAULT_LEAF_VALUES = generate_map_default_leaf_values();

//$client = new ContinusecClient("youraccount", "yoursecret");
//$map = $client->getVerifiableMap("phpmap");
//$map->set("foo", "bar");
//$map->setJson("json", json_encode((object)["name"=>"adam", "ssn"=>"123"]));
//$map->setRedactibleJson("redact", json_encode((object)["name"=>"adam", "ssn"=>"123"]));
//$map->create();
//$head = $map->getTreeHash();
//$val = $map->get("foo", $head->tree_size);
//var_dump($val);
//verify_map_inclusion_proof($head, $val);
//$val = $map->getJson("json", $head->tree_size);
//var_dump($val);
//verify_map_inclusion_proof($head, $val);
//$val = $map->getRedactedJson("redact", $head->tree_size);
//var_dump($val);
//verify_map_inclusion_proof($head, $val);

//$log = $client->getVerifiableLog("javalog");
//$log->create();
//$log->addEntry("hfoo");
//$log->addJsonEntry(json_encode(array("name"=>"adam", "ssn"=>"1234")));
//$log->addRedactibleJsonEntry(json_encode(array("name"=>"adam", "ssn"=>"1234")));
//$log->addEntry("baz");
//$head = $log->getTreeHash();
//$proof = $log->getInclusionProof($head->tree_size, leaf_merkle_tree_hash(object_hash_with_std_redaction((object)["name"=>"adam", "ssn"=>"1234"])));
//verify_log_inclusion_proof($head, $proof);
//$oldHead = $log->getTreeHash(1);
//$proof = $log->getConsistencyProof($oldHead->tree_size, $head->tree_size);
//verify_log_consistency_proof($oldHead, $head, $proof);

//echo $log->getEntry(1);
//foreach ($log->getEntries(0, $head->tree_size) as $x) {
//    echo $x . "\n";
//}

function object_hash_test($test_loc) {
	$f = fopen($test_loc, "r") or die("File not found");
	$state = 0;
	while (($line = fgets($f)) !== false) {
		$line = trim($line);
		if (strlen($line) > 0) {
			if ($line[0] != "#") {
				switch ($state) {
				case 0:
					$json = $line;
					$state = 1;
					break;
				case 1:
					$answer = $line;
					$x = object_hash_with_std_redaction(json_decode($json));
					if ($x == hex2bin($answer)) {
						echo "Match! - ".$json."\n";
					} else {
						echo "Fail! - ".$json."\n";
						//echo "got ".bin2hex($x)." expected ".$answer."\n";
					}
					$state = 0;
					break;
				}
			}
		}
	}
}

object_hash_test("../../objecthash/common_json.test");
?>
