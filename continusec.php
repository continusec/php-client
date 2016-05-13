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

function shed_std_redactability($o) {
	global $REDACTED_PREFIX;
	return shed_redactability($o, $REDACTED_PREFIX);
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
				$rv->$k = shed_redactability($v[1], $r);
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
		array_push($rv, shed_redactability($o[$i], $r));
	}
	return $rv;
}

function shed_redactability($o, $r) {
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

class ContinusecException extends Exception {}

class ObjectNotFoundException extends ContinusecException {}
class UnauthorizedAccessException extends ContinusecException {}
class ObjectConflictException extends ContinusecException {}
class VerificationFailedException extends ContinusecException {}
class InvalidRangeException extends ContinusecException {}
class InternalErrorException extends ContinusecException {}
class NotAllEntriesReturnedException extends ContinusecException {}

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

	/* not intended to be public, just for internal use by this package */
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
			throw new InvalidRangeException();
		} else if ($statusCode == 403) {
			throw new UnauthorizedAccessException();
		} else if ($statusCode == 404) {
			throw new ObjectNotFoundException();
		} else if ($statusCode == 409) {
			throw new ObjectConflictException();
		} else {
			throw new InternalErrorException();
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

	function setredactableJson($key, $value) {
		$this->client->makeRequest("PUT", $this->path . "/key/h/" . bin2hex($key) . "/xjson/redactable", $value);
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
		$rv->json = shed_std_redactability($rv->json);
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

class RawDataEntry {
	private $data;

	function RawDataEntry($data) {
		$this->data = $data;
	}

	function getFormat() {
		return "";
	}

	function getData() {
		return $this->data;
	}

	function getDataForUpload() {
		return $this->data;
	}

	function getLeafHash() {
		return leaf_merkle_tree_hash($this->data);
	}
}

class JsonEntry {
	private $data;

	function JsonEntry($json) {
		$this->data = $json;
	}

	function getFormat() {
		return "/xjson";
	}

	function getData() {
		return $this->data;
	}

	function getDataForUpload() {
		return $this->data;
	}

	function getLeafHash() {
		return leaf_merkle_tree_hash(object_hash_with_std_redaction(json_decode($this->data)));
	}
}

class RedactableJsonEntry {
	private $data;

	function RedactableJsonEntry($json) {
		$this->data = $json;
	}

	function getFormat() {
		return "/xjson/redactable";
	}

	function getDataForUpload() {
		return $this->data;
	}
}

class RedactedJsonEntry {
	private $data;

	function RedactedJsonEntry($json) {
		$this->data = $json;
	}

	function getData() {
		return json_encode(shed_std_redactability(json_decode($this->data)));
	}

	function getLeafHash() {
		return leaf_merkle_tree_hash(object_hash_with_std_redaction(json_decode($this->data)));
	}
}

class AddEntryResponse {
	private $leafHash;

	function AddEntryResponse($leafHash) {
		$this->leafHash = $leafHash;
	}

	function getLeafHash() {
		return $this->leafHash;
	}
}

class RawDataEntryFactory {
	function createFromBytes($bytes) {
		return new RawDataEntry($bytes);
	}

	function getFormat() {
		return "";
	}
}

class JsonEntryFactory {
	function createFromBytes($bytes) {
		return new JsonEntry($bytes);
	}

	function getFormat() {
		return "/xjson";
	}
}

class RedactedJsonEntryFactory {
	function createFromBytes($bytes) {
		return new RedactedJsonEntry($bytes);
	}

	function getFormat() {
		return "/xjson";
	}
}

class LogInclusionProof {
	private $treeSize;
	private $leafHash;
	private $leafIndex;
	private $auditPath;

	function LogInclusionProof($treeSize, $leafHash, $leafIndex, $auditPath) {
		$this->treeSize = $treeSize;
		$this->leafHash = $leafHash;
		$this->leafIndex = $leafIndex;
		$this->auditPath = $auditPath;
	}

	function getTreeSize() {
		return $this->treeSize;
	}

	function getLeafHash() {
		return $this->leafHash;
	}

	function getLeafIndex() {
		return $this->leafIndex;
	}

	function getAuditPath() {
		return $this->auditPath;
	}

	function verify($treeHead) {
		if (($this->leafIndex >= $treeHead->getTreeSize()) || ($this->leafIndex < 0)) {
			throw new VerificationFailedException("Invalid proof (1)");
		}
		if ($this->treeSize != $treeHead->getTreeSize()) {
			throw new VerificationFailedException("Invalid proof (4)");
		}

		$fn = intval($this->leafIndex);
		$sn = intval($this->treeSize) - 1;
		$r = $this->leafHash;

		foreach($this->auditPath as $p) {
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
			throw new VerificationFailedException("Invalid proof (2)");
		}

		if ($r != $treeHead->getRootHash()) {
			throw new VerificationFailedException("Invalid proof (3)");
		}
	}
}

class LogConsistencyProof {
	private $firstSize;
	private $secondSize;
	private $auditPath;

	function LogConsistencyProof($firstSize, $secondSize, $auditPath) {
		$this->firstSize = $firstSize;
		$this->secondSize = $secondSize;
		$this->auditPath = $auditPath;
	}

	function getFirstSize() {
		return $this->firstSize;
	}

	function getSecondSize() {
		return $this->secondSize;
	}

	function getAuditPath() {
		return $this->auditPath;
	}

	function verify($firstTreeHead, $secondTreeHead) {
		if ($firstTreeHead->getTreeSize() != $this->firstSize) {
			throw new VerificationFailedException("Invalid proof (10)");
		}
		if ($secondTreeHead->getTreeSize() != $this->secondSize) {
			throw new VerificationFailedException("Invalid proof (11)");
		}
		if (($firstTreeHead->getTreeSize() < 1) || ($firstTreeHead->getTreeSize() >= $secondTreeHead->getTreeSize())) {
			throw new VerificationFailedException("Invalid proof (4)");
		}

		$proof = $this->auditPath; // since PHP arrays are copy on assign, we have a copy!
		if (is_pow_2($firstTreeHead->getTreeSize())) {
			array_unshift($proof, $firstTreeHead->getRootHash());
		}

		$fn = $this->firstSize - 1;
		$sn = $this->secondSize - 1;

		while (($fn & 1) == 1) {
			$fn >>= 1;
			$sn >>= 1;
		}

		if (count($proof) == 0) {
			throw new VerificationFailedException("Invalid proof (5)");
		}

		$fr = $proof[0];
		$sr = $proof[0];

		for ($i = 1; $i < count($proof); $i++) {
			if ($sn == 0) {
				throw new VerificationFailedException("Invalid proof (6)");
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
			throw new VerificationFailedException("Invalid proof (7)");
		}

		if ($fr != $firstTreeHead->getRootHash()) {
			throw new VerificationFailedException("Invalid proof (8)");
		}

		if ($sr != $secondTreeHead->getRootHash()) {
			throw new VerificationFailedException("Invalid proof (9)");
		}
	}
}

class LogTreeHead {
	private $treeSize;
	private $rootHash;

	function LogTreeHead($treeSize, $rootHash) {
		$this->treeSize = $treeSize;
		$this->rootHash = $rootHash;
	}

	function getTreeSize() {
		return $this->treeSize;
	}

	function getRootHash() {
		return $this->rootHash;
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

	function getTreeHead($treeSize=0) {
		$obj = json_decode($this->client->makeRequest("GET", $this->path . "/tree/" . $treeSize, null)["body"]);
		return new LogTreeHead($obj->tree_size, base64_decode($obj->tree_hash));
	}

	function getInclusionProof($treeSize, $leafHash) {
		$obj = json_decode($this->client->makeRequest("GET", $this->path . "/tree/" . $treeSize . "/inclusion/h/" . bin2hex($leafHash), null)["body"]);
		$auditPath = array();
		foreach ($obj->proof as $p) {
		    array_push($auditPath, base64_decode($p));
		}
		return new LogInclusionProof($treeSize, $leafHash, $obj->leaf_index, $auditPath);
	}

	function getInclusionProofByIndex($treeSize, $leafIndex) {
		$obj = json_decode($this->client->makeRequest("GET", $this->path . "/tree/" . $treeSize . "/inclusion/" . $leafIndex, null)["body"]);
		$auditPath = array();
		foreach ($obj->proof as $p) {
		    array_push($auditPath, base64_decode($p));
		}
		return new LogInclusionProof($treeSize, null, $obj->leaf_index, $auditPath);
	}

	function getConsistencyProof($firstSize, $secondSize) {
		$obj = json_decode($this->client->makeRequest("GET", $this->path . "/tree/" . $secondSize . "/consistency/" . $firstSize, null)["body"]);
		$auditPath = array();
		foreach ($obj->proof as $p) {
		    array_push($auditPath, base64_decode($p));
		}
		return new LogConsistencyProof($firstSize, $secondSize, $auditPath);
	}

	function addEntry($entry) {
		$obj = json_decode($this->client->makeRequest("POST", $this->path . "/entry" . $entry->getFormat(), $entry->getDataForUpload())["body"]);
		return new AddEntryResponse(base64_decode($obj->leaf_hash));
	}

	function getEntry($idx, $factory) {
		return $factory->createFromBytes($this->client->makeRequest("GET", $this->path . "/entry/" . $idx . $factory->getFormat(), null)["body"]);
	}

	function getEntries($startIdx, $endIdx, $factory) {
	    $rv = array();
		foreach (json_decode($this->client->makeRequest("GET", $this->path . "/entries/" . $startIdx . "-" . $endIdx . $factory->getFormat(), null)["body"])->entries as $a) {
		    array_push($rv, $factory->createFromBytes(base64_decode($a->leaf_data)));
		}
		return $rv;
	}

	function blockUntilPresent($mtlHash) {
		$lastHead = -1;
		$secsToSleep = 0;
		while (true) {
			$lth = $this->getTreeHead(0);
			if ($lth->getTreeSize() > $lastHead) {
				$lastHead = $lth->getTreeSize();
				try {
					if ($this->getInclusionProof($lth->getTreeSize(), $mtlHash) != null) {
						return $lth;
					}
				} catch (InvalidRangeException $e) {
					// not present yet, ignore
				}
				// since we got a new tree head, reset sleep time
				$secsToSleep = 1;
			} else {
				// no luck, snooze a bit longer
				$secsToSleep *= 2;
			}
			sleep($secsToSleep);
		}
	}

	function fetchVerifiedTreeHead($prev) {
		// Fetch latest from server
		$head = $this->getTreeHead(0);

		// If the new hash no later than our current one,
		if ($head->getTreeSize() <= $prev->getTreeSize()) {
			// return our current one
			return $prev;
		} else { // verify consistency with new one
			// If previous is zero, then skip consistency check
			if ($prev->getTreeSize() != 0) {
				 // First fetch a consistency proof from the server
				$p = $this->getConsistencyProof($prev->getTreeSize(), $head->getTreeSize());

				// Verify the consistency proof
				$p->verify($prev, $head);
			}
			return $head;
		}
	}

	function verifySuppliedInclusionProof($prev, $proof) {
		$headForInclProof = null;
		if ($proof->getTreeSize() == $prev->getTreeSize()) {
			$headForInclProof = $prev;
		} else {
			$headForInclProof = $this->getTreeHead($proof->getTreeSize());
			if ($prev->getTreeSize() != 0) { // so long as prev is not special value, check consistency
				if ($prev->getTreeSize() < $headForInclProof->getTreeSize()) {
					$p = $this->getConsistencyProof($prev->getTreeSize(), $headForInclProof->getTreeSize());
					$p->verify($prev, $headForInclProof);
				} else if ($prev->getTreeSize() > $headForInclProof->getTreeSize()) {
					$p = $this->getConsistencyProof($headForInclProof->getTreeSize(), $prev->getTreeSize());
					$p->verify($headForInclProof, $prev);
				} else { // should not get here
					throw new VerificationFailedException();
				}
			}
		}
		$proof->verify($headForInclProof);
		return $headForInclProof;
	}

	function auditLogEntries($prev, $head, $factory, $auditor) {
		if (($prev == null) || $prev->getTreeSize() < $head->getTreeSize()) {
			$merkleTreeStack = [];
			if (($prev != null) && ($prev->getTreeSize() > 0)) {
				$p = $this->getInclusionProofByIndex($prev->getTreeSize()+1, $prev->getTreeSize());
				$firstHash = null;
				$path = $p->getAuditPath();
				foreach ($path as $b) {
					if ($firstHash == null) {
						$firstHash = $b;
					} else {
						$firstHash = node_merkle_tree_hash($b, $firstHash);
					}
				}
				if ($firstHash != $prev->getRootHash()) {
					throw new VerificationFailedException();
				}
				for ($i = count($path) - 1; $i >= 0; $i--) {
					array_push($merkleTreeStack, $path[$i]);
				}
			}

			$idx = ($prev == null) ? 0 : $prev->getTreeSize();
			$entries = $this->getEntries($idx, $head->getTreeSize(), $factory);
			foreach ($entries as $e) {
				// do whatever content audit is desired on e
				$auditor->auditLogEntry($idx, $e);

				// update the merkle tree hash stack:
				array_push($merkleTreeStack, $e->getLeafHash());
				for ($z = $idx; ($z & 1) == 1; $z >>= 1) {
					$right = array_pop($merkleTreeStack);
					$left = array_pop($merkleTreeStack);
					array_push($merkleTreeStack, node_merkle_tree_hash($left, $right));
				}
				$idx++;
			}

			if ($idx != $head->getTreeSize()) {
				throw new NotAllEntriesReturnedException();
			}

			$headHash = array_pop($merkleTreeStack);
			while (count($merkleTreeStack) > 0) {
				$headHash = node_merkle_tree_hash(array_pop($merkleTreeStack), $headHash);
			}

			if ($headHash != $head->getRootHash()) {
				throw new VerificationFailedException();
			}
		}
	}
}

function leaf_merkle_tree_hash($b) {
    return hash("sha256", chr(0) . $b, true);
}

function node_merkle_tree_hash($l, $r) {
    return hash("sha256", chr(1) . $l . $r, true);
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
?>
