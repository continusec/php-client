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

/**
 * @ignore
 */
$NORMALIZE_FUNC = function ($o) { return $o; };
if (function_exists("normalizer_normalize")) {
	$NORMALIZE_FUNC = function($o) { return normalizer_normalize($o, Normalizer::FORM_C); };
} else {
	error_log("WARNING: normalizer_normalize (part of php-intl package) is required for proper unicode normalization for objecthash. Proceeding without, so non-ASCII characters may not verify correctly.", 0);
}

if (!function_exists("curl_init")) {
	error_log("ERROR: curl_init not found. Without this the Continusec library can't make outbound connections.", 0);
}

/**
 * @ignore
 */
$REDACTED_PREFIX = "***REDACTED*** Hash: ";

/**
 * @ignore
 * PHP doesn't distinguish between a list and a map - sigh, so here is our best attempt
 */
function is_array_a_list($o, $def) {
	$keys = array_keys($o);
	if (count($keys) == 0) {
		return $def; /* ambiguous, caller gives us best guess */
	} else {
		return $keys === range(0, count($o)-1);
	}
}

/**
 * @ignore
 */
function object_hash_list_with_redaction($o, $r) {
	$rv = "l";
	for ($i = 0; $i < count($o); $i++) {
		$rv .= object_hash_with_redaction($o[$i], $r);
	}
	return hash("sha256", $rv, true);
}

/**
 * @ignore
 */
function object_hash_map_with_redaction($o, $r) {
	$keys = array_keys($o);
	$kvs = array();
	for ($i = 0; $i < count($keys); $i++) {
		array_push($kvs, object_hash_with_redaction($keys[$i], $r).object_hash_with_redaction($o[$keys[$i]], $r));
	}
	sort($kvs);
	return hash("sha256", "d".join("", $kvs), true);
}

/**
 * @ignore
 */
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

/**
 * Calculate the objecthash for an object, with a custom redaction prefix string.
 * @param mixed $o the object to calculate the objecthash for.
 * @param string $r the string to use as a prefix to indicate that a string should be treated as a redacted subobject.
 * @return string the objecthash for this object
 */
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

/**
 * Calculate the objecthash for an object, assuming no redaction,
 * @param mixed $o the object to calculate the objecthash for.
 * @return string the objecthash for this object
 */
function object_hash($o) {
	return object_hash_with_redaction($o, "");
}

/**
 * Calculate the objecthash for an object, with standard redaction prefix string.
 * @param mixed $o the object to calculate the objecthash for.
 * @return string the objecthash for this object
 */
function object_hash_with_std_redaction($o) {
	global $REDACTED_PREFIX;
	return object_hash_with_redaction($o, $REDACTED_PREFIX);
}

/**
 * Strip away object values that are marked as redacted, and switch nonce-tuples back to normal values.
 * This is useful when an object has been stored with Redactable nonces added, but now it has been retrieved
 * and normal processing needs to be performed on it. This method uses the standard redaction prefix.
 * @param mixed $o the object that contains the redacted elements and nonce-tuples.
 * @return mixed a new cleaned up object
 */
function shed_std_redactability($o) {
	global $REDACTED_PREFIX;
	return shed_redactability($o, $REDACTED_PREFIX);
}

/**
 * @ignore
 */
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

/**
 * @ignore
 */
function unredact_list($o, $r) {
	$rv = array();
	for ($i = 0; $i < count($o); $i++) {
		array_push($rv, shed_redactability($o[$i], $r));
	}
	return $rv;
}

/**
 * Strip away object values that are marked as redacted, and switch nonce-tuples back to normal values.
 * This is useful when an object has been stored with Redactable nonces added, but now it has been retrieved
 * and normal processing needs to be performed on it.
 * @param mixed $o the object that contains the redacted elements and nonce-tuples.
 * @param string $r the redaction prefix that indicates if a string represents a redacted sub-object.
 * @return mixed a new cleaned up object
 */
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

/**
 * Base exception class used for all Continusec exceptions.
 */
class ContinusecException extends Exception {}

/**
 * Indicates the object cannot be found.
 */
class ObjectNotFoundException extends ContinusecException {}

/**
 * Indicates that either the wrong API Key is being used, or the account is suspended for other reasons (check billing status in console).
 */
class UnauthorizedAccessException extends ContinusecException {}

/**
 * Indicates that object being modified already exists.
 */
class ObjectConflictException extends ContinusecException {}

/**
 * Indicates the verification of a proof has failed.
 */
class VerificationFailedException extends ContinusecException {}

/**
 * Indicates invalid size or range in the request, e.g. tree size too large or small.
 */
class InvalidRangeException extends ContinusecException {}

/**
 * Indicates internal error that occurred on the server.
 */
class InternalErrorException extends ContinusecException {}

/**
 * Indicates that not all entries were returned. Typically due to requesting Json, but not
 * storing as such.
 */
class NotAllEntriesReturnedException extends ContinusecException {}

/**
 * Main entry point for interacting with Continusec's Verifiable Data Structure APIs.
 */
class ContinusecClient {
	/**
	 * @ignore
	 */
	private $account;
	/**
	 * @ignore
	 */
	private $apiKey;
	/**
	 * @ignore
	 */
	private $baseUrl;

	/**
	 * Create a ContinusecClient for a given account with specified API Key and custom
	 * base URL. This is normally only used for unit tests of the ContinusecClient API.
	 *
	 * @param string $account the account number, found on the "Settings" tab in the console.
	 * @param string $apiKey the API Key, found on the "API Keys" tab in the console.
	 * @param string $baseUrl the base URL to send API requests to.
	 */
	function ContinusecClient($account, $apiKey, $baseUrl="https://api.continusec.com") {
		$this->account = $account;
		$this->apiKey = $apiKey;
		$this->baseUrl = $baseUrl;
	}

	/**
	 * Return a pointer to a verifiable log that belongs to this account.
	 *
	 * @param string $name name of the log to access.
	 * @return VerifiableLog an object that allows manipulation of the specified log.
	 */
	public function getVerifiableLog($name) {
		return new VerifiableLog($this, "/log/".$name);
	}

	/**
	 * Return a pointer to a verifiable map that belongs to this account.
	 *
	 * @param string $name name of the map to access.
	 * @return VerifiableMap an object that allows manipulation of the specified map.
	 */
	public function getVerifiableMap($name) {
		return new VerifiableMap($this, "/map/".$name);
	}

	/**
	 * @ignore
	 * not intended to be public, just for internal use by this package
	 */
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

/**
 * @ignore
 */
class VerifiableMap {
	/**
	 * @ignore
	 */
	private $client;
	/**
	 * @ignore
	 */
	private $path;

	/**
	 * @ignore
	 */
	function VerifiableMap($client, $path) {
		$this->client = $client;
		$this->path = $path;
	}

	/**
	 * @ignore
	 */
	function create() {
		$this->client->makeRequest("PUT", $this->path, null);
	}

	/**
	 * @ignore
	 */
	function getMutationLog() {
		return new VerifiableLog($this->client, $this->path."/log/mutation");
	}

	/**
	 * @ignore
	 */
	function getTreeHeadLog() {
		return new VerifiableLog($this->client, $this->path."/log/treehead");
	}

	/**
	 * @ignore
	 */
	function set($key, $entry) {
		$obj = json_decode($this->client->makeRequest("PUT", $this->path . "/key/h/" . bin2hex($key) . $entry->getFormat(), $entry->getDataForUpload())["body"]);
		return new AddEntryResponse(base64_decode($obj->leaf_hash));
	}

	/**
	 * @ignore
	 */
	function delete($key) {
		$obj = json_decode($this->client->makeRequest("DELETE", $this->path . "/key/h/" . bin2hex($key), null)["body"]);
		return new AddEntryResponse(base64_decode($obj->leaf_hash));
	}


	/**
	 * @ignore
	 */
	function get($key, $mapHead, $factory) {
		$treeSize = $mapHead->getMutationLogTreeHead()->getTreeSize();
		$rv = $this->client->makeRequest("GET", $this->path . "/tree/" . $treeSize . "/key/h/" . bin2hex($key) . $factory->getFormat(), null);

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
		$pos = strpos($lwrHdr, "\r\nx-verified-treesize:", 0);
		if ($pos !== false) {
			$end = strpos($lwrHdr, "\r\n", $pos + 22);
			$part = trim(substr($lwrHdr, $pos + 22, $end - ($pos + 22)));
			$actTreeSize = intval($part);
		}

		return new MapGetEntryResponse($key, $factory->createFromBytes($rv["body"]), $actTreeSize, $auditPath);
	}

	/**
	 * @ignore
	 */
	function getTreeHead($treeSize=0) {
		$obj = json_decode($this->client->makeRequest("GET", $this->path . "/tree/" . $treeSize, null)["body"]);
		return new MapTreeHead(base64_decode($obj->map_hash), new LogTreeHead($obj->mutation_log->tree_size, base64_decode($obj->mutation_log->tree_hash)));
	}

	function blockUntilSize($treeSize) {
		$lastHead = -1;
		$secsToSleep = 0;
		while (true) {
			$lth = $this->getTreeHead(0);
			if ($lth->getMutationLogTreeHead()->getTreeSize() > $lastHead) {
				$lastHead = $lth->getMutationLogTreeHead()->getTreeSize();
				if ($lastHead >= $treeSize) {
					return $lth;
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
}

class MapGetEntryResponse {
	private $key, $value, $treeSize, $auditPath;

	function MapGetEntryResponse($key, $value, $treeSize, $auditPath) {
		$this->key = $key;
		$this->value = $value;
		$this->treeSize = $treeSize;
		$this->auditPath = $auditPath;
	}

	function getKey() {
		return $this->key;
	}

	function getValue() {
		return $this->value;
	}

	function getTreeSize() {
		return $this->treeSize;
	}

	function getAuditPath() {
		return $this->auditPath;
	}

	function verify($head) {
		global $DEFAULT_LEAF_VALUES;

		if ($head->getMutationLogTreeHead()->getTreeSize() != $this->treeSize) {
			throw new VerificationFailedException("Invalid proof (21)");
		}

		$kp = construct_map_key_path($this->key);
		$t = $this->value->getLeafHash();
		for ($i = 255; $i >= 0; $i--) {
			$p = $this->auditPath[$i];
			if ($p == null) {
				$p = $DEFAULT_LEAF_VALUES[$i+1];
			}
			if ($kp[$i]) {
				$t = node_merkle_tree_hash($p, $t);
			} else {
				$t = node_merkle_tree_hash($t, $p);
			}
		}

		if ($t != $head->getRootHash()) {
			throw new VerificationFailedException("Invalid proof (20)");
		}
	}
}

/**
 * Class to represent a log/map entry where no special processing is performed,
 * that is, the bytes specified are stored as-is, and are used as-is for input
 * to the Merkle Tree leaf function.
 */
class RawDataEntry {
	/**
	 * @ignore
	 */
	private $data;

	/**
	 * Construct a new RawDataEntry with the specified rawData.
	 * @param string $data the raw data.
	 */
	function RawDataEntry($data) {
		$this->data = $data;
	}

	/**
	 * Get the suffix that should be added to the PUT/POST request for this data format.
	 * @return string the suffix
	 */
	function getFormat() {
		return "";
	}

	/**
	 * Get the data for processing.
	 * @return string the raw data
	 */
	function getData() {
		return $this->data;
	}

	/**
	 * Get the data that should be stored.
	 * @return string the raw data
	 */
	function getDataForUpload() {
		return $this->data;
	}

	/**
	 * Calculate the leaf hash for this entry.
	 * @return string the Merkle Tree leaf hash for this entry.
	 */
	function getLeafHash() {
		return leaf_merkle_tree_hash($this->data);
	}
}

/**
 * Class to be used when entry MerkleTreeLeafs should be based on ObjectHash
 * rather than the JSON bytes directly. Since there is no canonical encoding for JSON,
 * it is useful to hash these objects in a more defined manner.
 */
class JsonEntry {
	/**
	 * @ignore
	 */
	private $data;

	/**
	 * Create entry object based on raw JSON data.
	 * @param string $json the raw JSON data.
	 */
	function JsonEntry($json) {
		$this->data = $json;
	}

	/**
	 * Returns the format suffix needed for the internal POST to /entry.
	 * @return string format suffix
	 */
	function getFormat() {
		return "/xjson";
	}

	/**
	 * Get data for processing.
	 * @return string the raw data
	 */
	function getData() {
		return $this->data;
	}

	/**
	 * Get the data that should be stored.
	 * @return string the raw data
	 */
	function getDataForUpload() {
		return $this->data;
	}

	/**
	 * Calculate the leaf hash for this entry.
	 * @return string the Merkle Tree leaf hash for this entry.
	 */
	function getLeafHash() {
		return leaf_merkle_tree_hash(object_hash_with_std_redaction(json_decode($this->data)));
	}
}

/**
 * Class to represent JSON data should be made Redactable by the server upon upload.
 * ie change all dictionary values to be nonce-value tuples and control access to fields
 * based on the API key used to make the request.
 */
class RedactableJsonEntry {
	/**
	 * @ignore
	 */
	private $data;

	/**
	 * Create a new entry based on rawData JSON.
	 * @param string $json representing the JSON for this entry.
	 */
	function RedactableJsonEntry($json) {
		$this->data = $json;
	}

	/**
	 * Returns the format suffix needed for the internal POST to /entry.
	 * @return string format suffix
	 */
	function getFormat() {
		return "/xjson/redactable";
	}

	/**
	 * Get the data that should be stored.
	 * @return string the raw data
	 */
	function getDataForUpload() {
		return $this->data;
	}
}

/**
 * Class to represent redacted entries as returned by the server. Not to be confused
 * with RedactableJsonEntry that should be used to represent objects that should
 * be made Redactable by the server when uploaded.
 */
class RedactedJsonEntry {
	/**
	 * @ignore
	 */
	private $data;

	/**
	 * Package private constructor. Unlike the other Entry types, this should be considered package
	 * private to prevent accidentaly confusion with RedactableJsonEntry.
	 * which is what should be used to create an entry for upload.
	 * @param string $json the raw data respresenting the redacted JSON.
	 */
	function RedactedJsonEntry($json) {
		$this->data = $json;
	}

	/**
	 * Get the underlying JSON for this entry, with all Redactable nonce-tuples and
	 * redacted sub-objects stripped for ease of processing.
	 * @return string the JSON with with Redactable artefacts shed.
	 */
	function getData() {
		return json_encode(shed_std_redactability(json_decode($this->data)));
	}

	/**
	 * Calculate the leaf hash for this entry.
	 * @return string the Merkle Tree leaf hash for this entry.
	 */
	function getLeafHash() {
		return leaf_merkle_tree_hash(object_hash_with_std_redaction(json_decode($this->data)));
	}
}

/**
 * Response from adding entries to a log/map.
 */
class AddEntryResponse {
	/**
	 * @ignore
	 */
	private $leafHash;

	/**
	 * Package private constructor. Use VerifiableLog->addEntry to instantiate.
	 * @param string $leafHash leaf hash of the entry.
	 */
	function AddEntryResponse($leafHash) {
		$this->leafHash = $leafHash;
	}

	/**
	 * Get the leaf hash for this entry.
	 * @return string the leaf hash for this entry.
	 */
	function getLeafHash() {
		return $this->leafHash;
	}
}

/**
 * Factory that produces RawDataEntry instances upon request.
 */
class RawDataEntryFactory {
	/**
	 * Instantiate a new entry from bytes as returned by server.
	 * @param string $bytes the bytes as returned by the server.
	 * @return RawDataEntry the new entry.
	 */
	function createFromBytes($bytes) {
		return new RawDataEntry($bytes);
	}

	/**
	 * Returns the suffix added to calls to GET /entry/xxx
	 * @return string the suffix to add.
	 */
	function getFormat() {
		return "";
	}
}

/**
 * Factory that produces JsonEntry instances upon request.
 */
class JsonEntryFactory {
	/**
	 * Instantiate a new entry from bytes as returned by server.
	 * @param string $bytes the bytes as returned by the server.
	 * @return RawDataEntry the new entry.
	 */
	function createFromBytes($bytes) {
		return new JsonEntry($bytes);
	}

	/**
	 * Returns the suffix added to calls to GET /entry/xxx
	 * @return string the suffix to add.
	 */
	function getFormat() {
		return "/xjson";
	}
}

/**
 * Factory that produces RedactedJsonEntry instances upon request.
 */
class RedactedJsonEntryFactory {
	/**
	 * Instantiate a new entry from bytes as returned by server.
	 * @param string $bytes the bytes as returned by the server.
	 * @return RawDataEntry the new entry.
	 */
	function createFromBytes($bytes) {
		return new RedactedJsonEntry($bytes);
	}

	/**
	 * Returns the suffix added to calls to GET /entry/xxx
	 * @return string the suffix to add.
	 */
	function getFormat() {
		return "/xjson";
	}
}

/**
 * Class to represent proof of inclusion of an entry in a log.
 */
class LogInclusionProof {
	/**
	 * @ignore
	 */
	private $treeSize;
	/**
	 * @ignore
	 */
	private $leafHash;
	/**
	 * @ignore
	 */
	private $leafIndex;
	/**
	 * @ignore
	 */
	private $auditPath;

	/**
	 * Create new LogInclusionProof.
	 *
	 * @param int $treeSize the tree size for which this proof is valid.
	 * @param string $leafHash the Merkle Tree Leaf hash of the entry this proof is valid for.
	 * @param int $leafIndex the index of this entry in the log.
	 * @param array[] $auditPath the set of Merkle Tree nodes that apply to this entry in order to generate the root hash and prove inclusion.
	 */
	function LogInclusionProof($treeSize, $leafHash, $leafIndex, $auditPath) {
		$this->treeSize = $treeSize;
		$this->leafHash = $leafHash;
		$this->leafIndex = $leafIndex;
		$this->auditPath = $auditPath;
	}

	/**
	 * Returns the tree size.
	 * @return int the tree size.
	 */
	function getTreeSize() {
		return $this->treeSize;
	}

	/**
	 * Returns the leaf hash
	 * @return string the leaf hash
	 */
	function getLeafHash() {
		return $this->leafHash;
	}

	/**
	 * Returns the leaf index.
	 * @return int the leaf index.
	 */
	function getLeafIndex() {
		return $this->leafIndex;
	}

	/**
	 * Returns the audit path.
	 * @return array[] the audit path for this proof.
	 */
	function getAuditPath() {
		return $this->auditPath;
	}

	/**
	 * For a given tree head, compare the root hash calculated by this proof to verify the tree head.
	 * @param LogTreeHead $treeHead the tree head.
	 */
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

/**
 * Class to represent the result of a call to VerifiableLog->getConsistencyProof().
 */
class LogConsistencyProof {
	/**
	 * @ignore
	 */
	private $firstSize;
	/**
	 * @ignore
	 */
	private $secondSize;
	/**
	 * @ignore
	 */
	private $auditPath;

	/**
	 * Creates a new LogConsistencyProof for given tree sizes and auditPath.
	 * @param int $firstSize the size of the first tree.
	 * @param int $secondSize the size of the second tree.
	 * @param array[] $auditPath the audit proof returned by the server.
	 */
	function LogConsistencyProof($firstSize, $secondSize, $auditPath) {
		$this->firstSize = $firstSize;
		$this->secondSize = $secondSize;
		$this->auditPath = $auditPath;
	}

	/**
	 * Returns the size of the first tree.
	 * @return int the size of the first tree.
	 */
	function getFirstSize() {
		return $this->firstSize;
	}

	/**
	 * Returns the size of the second tree.
	 * @return int the size of the second tree.
	 */
	function getSecondSize() {
		return $this->secondSize;
	}

	/**
	 * Returns the audit path.
	 * @return array[] the audit path.
	 */
	function getAuditPath() {
		return $this->auditPath;
	}

	/**
	 * Verify that the consistency proof stored in this object can produce both the LogTreeHeads passed to this method.
	 * i.e, verify the append-only nature of the log between first.getTreeSize() and second.getTreeSize().
	 * @param LogTreeHead $firstTreeHead the tree hash for the first tree size
	 * @param LogTreeHead $secondTreeHead the tree hash for the second tree size
	 * @throws ContinusecException (most commonly VerificationFailedException) if the verification fails for any reason.
	 */
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

/**
 * Class for Tree Hash as returned for a log with a given size.
 */
class LogTreeHead {
	/**
	 * @ignore
	 */
	private $treeSize;
	/**
	 * @ignore
	 */
	private $rootHash;

	/**
	 * Constructor.
	 * @param int $treeSize the tree size the root hash is valid for.
	 * @param string $rootHash the root hash for the log of this tree size.
	 */
	function LogTreeHead($treeSize, $rootHash) {
		$this->treeSize = $treeSize;
		$this->rootHash = $rootHash;
	}

	/**
	 * Returns the tree size for this tree hash.
	 * @return int the tree size for this tree hash.
	 */
	function getTreeSize() {
		return $this->treeSize;
	}

	/**
	 * Returns the root hash for this tree size.
	 * @return string the root hash for this tree size.
	 */
	function getRootHash() {
		return $this->rootHash;
	}

}

class MapTreeHead {
	private $mutationLogTreeHead;
	private $rootHash;

	function MapTreeHead($rootHash, $mutationLogTreeHead) {
		$this->rootHash = $rootHash;
		$this->mutationLogTreeHead = $mutationLogTreeHead;
	}

	function getMutationLogTreeHead() {
		return $this->mutationLogTreeHead;
	}

	function getRootHash() {
		return $this->rootHash;
	}
}


/**
 * Class to interact with verifiable logs. Instantiate by callling ContinusecClient->getVerifiableLog().
 */
class VerifiableLog {
	/**
	 * @ignore
	 */
	private $client;
	/**
	 * @ignore
	 */
	private $path;

	/**
	 * Package private constructor. Use  ContinusecClient->getVerifiableLog() to instantiate.
	 * @param ContinusecClient $client the client (used for requests) that this log belongs to
	 * @param string $path the relative path to the log.
	 */
	function VerifiableLog($client, $path) {
		$this->client = $client;
		$this->path = $path;
	}

	/**
	 * Send API call to create this log. This should only be called once, and subsequent
	 * calls will cause an exception to be generated.
	 */
	function create() {
		$this->client->makeRequest("PUT", $this->path, null);
	}

	/**
	 * Get the tree hash for given tree size.
	 *
	 * @param int $treeSize the tree size to retrieve the hash for. Pass 0 to get the
	 * latest tree size.
	 * @return LogTreeHead the tree hash for the given size (includes the tree size actually used, if unknown before running the query).
	 */
	function getTreeHead($treeSize=0) {
		$obj = json_decode($this->client->makeRequest("GET", $this->path . "/tree/" . $treeSize, null)["body"]);
		return new LogTreeHead($obj->tree_size, base64_decode($obj->tree_hash));
	}

	/**
	 * Get an inclusion proof for a given item.
	 * @param int $treeSize the tree size for which the inclusion proof should be returned. This is usually as returned by LogTreeHead->getTreeSize().
	 * @param string $leafHash the entry for which the inclusion proof should be returned. Note that AddEntryResponse, and the *Entry classes implement getLeafHash().
	 * @return LogInclusionProof a log inclusion proof object that can be verified against a given tree hash.
	 */
	function getInclusionProof($treeSize, $leafHash) {
		$obj = json_decode($this->client->makeRequest("GET", $this->path . "/tree/" . $treeSize . "/inclusion/h/" . bin2hex($leafHash), null)["body"]);
		$auditPath = array();
		foreach ($obj->proof as $p) {
			array_push($auditPath, base64_decode($p));
		}
		return new LogInclusionProof($treeSize, $leafHash, $obj->leaf_index, $auditPath);
	}

	/**
	 * Get an inclusion proof for a specified tree size and leaf index. This is not used by typical clients,
	 * however it can be useful for audit operations and debugging tools. Typical clients will use getInclusionProof(treeSize, leafHash).
	 * @param int $treeSize the tree size on which to base the proof.
	 * @param int $leafIndex the leaf index for which to retrieve the inclusion proof.
	 * @return LogInclusionProof a partially filled in LogInclusionProof (note it will not include the MerkleTreeLeaf hash for the item).
	 */
	function getInclusionProofByIndex($treeSize, $leafIndex) {
		$obj = json_decode($this->client->makeRequest("GET", $this->path . "/tree/" . $treeSize . "/inclusion/" . $leafIndex, null)["body"]);
		$auditPath = array();
		foreach ($obj->proof as $p) {
			array_push($auditPath, base64_decode($p));
		}
		return new LogInclusionProof($treeSize, null, $obj->leaf_index, $auditPath);
	}

	/**
	 * Get an consistency proof to show how a log is append-only between two LogTreeHeads.
	 * @param int $firstSize the first log tree hash, typically retrieved by getTreeHead()->getTreeSize() and persisted.
	 * @param int #secondSize the second log tree hash, also retrieved by getTreeHead()->getTreeSize() and persisted once verified.
	 * @return LogConsistencyProof a log consistency proof object that must be verified.
	 */
	function getConsistencyProof($firstSize, $secondSize) {
		$obj = json_decode($this->client->makeRequest("GET", $this->path . "/tree/" . $secondSize . "/consistency/" . $firstSize, null)["body"]);
		$auditPath = array();
		foreach ($obj->proof as $p) {
			array_push($auditPath, base64_decode($p));
		}
		return new LogConsistencyProof($firstSize, $secondSize, $auditPath);
	}

	/**
	 * Send API call to add an entry to the log. Note the entry is added asynchronously, so while
	 * the library will return as soon as the server acknowledges receipt of entry, it may not be
	 * reflected in the tree hash (or inclusion proofs) until the server has sequenced the entry.
	 *
	 * @param mixed $entry the entry to add, often RawDataEntry, JsonEntry or RedactableJsonEntry.
	 * @return AddEntryResponse add entry response, which includes the Merkle Tree Leaf hash of the entry added.
	 */
	function addEntry($entry) {
		$obj = json_decode($this->client->makeRequest("POST", $this->path . "/entry" . $entry->getFormat(), $entry->getDataForUpload())["body"]);
		return new AddEntryResponse(base64_decode($obj->leaf_hash));
	}

	/**
	 * Get the entry at the specified index.
	 *
	 * @param int $idx the index to retrieve (starts at zero).
	 * @param mixed $factory the type of entry to return, usually one of new RawDataEntryFactory(), new JsonEntryFactory() or new RedactedJsonEntryFactory().
	 * @return string the entry requested.
	 */
	function getEntry($idx, $factory) {
		return $factory->createFromBytes($this->client->makeRequest("GET", $this->path . "/entry/" . $idx . $factory->getFormat(), null)["body"]);
	}

	/**
	 * Returns multiple entries. If for any
	 * reason not all entries are returned, the array will be shorter than the amount requested.
	 *
	 * @param int $startIdx the first entry to return
	 * @param int $endIdx the last entry to return
	 * @param mixed $factory the type of entry to return, usually one of new RawDataEntryFactory(), new JsonEntryFactory() or new RedactedJsonEntryFactory().
	 * @return array[] an array for the entries requested.
	 */
	function getEntries($startIdx, $endIdx, $factory) {
		$rv = array();
		foreach (json_decode($this->client->makeRequest("GET", $this->path . "/entries/" . $startIdx . "-" . $endIdx . $factory->getFormat(), null)["body"])->entries as $a) {
			array_push($rv, $factory->createFromBytes(base64_decode($a->leaf_data)));
		}
		return $rv;
	}

	/**
	 * Block until the log is able to produce a LogTreeHead that includes the specified $mtlHash.
	 * This polls getTreeHead() and getInclusionProof() until
	 * such time as a new tree hash is produced that includes the given $mtlHash. Exponential back-off
	 * is used when no tree hash is available. This is intended for test use.
	 * @param string $mtlHash the leaf we should block until included. Typically this is a from an AddEntryResponse as returned by addEntry().
	 * @return LogTreeHead the first tree hash that includes this leaf (proof is not verified).
	 */
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

	/**
	 * FetchVerifiedTreeHead is a utility method to fetch a new LogTreeHead and verifies that it is consistent with
	 * a tree head earlier fetched and persisted. To avoid potentially masking client tree head storage issues,
	 * it is an error to pass null. For first use, pass new LogTreeHead(0, null), which will bypass consistency proof checking.
	 * @param LogTreeHead $prev a previously persisted log tree head, or special value new LogTreeHead(0, null) on first run.
	 * @return LogTreeHead a new tree head, which has been verified to be consistent with the past tree head, or if no newer one present, the same value as passed in.
	 */
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

	/**
	 * VerifySuppliedInclusionProof is a utility method that fetches any required tree heads that are needed
	 * to verify a supplied log inclusion proof. Additionally it will ensure that any fetched tree heads are consistent
	 * with any prior supplied LogTreeHead.  o avoid potentially masking client tree head storage issues,
	 * it is an error to pass null. For first use, pass new LogTreeHead(0, null), which will
	 * bypass consistency proof checking.
	 * @param LogTreeHead $prev a previously persisted log tree head, or special value new LogTreeHead(0, null)
	 * @param LogInclusionProof $proof an inclusion proof that may be for a different tree size than prev.getTreeSize()
	 * @return LogTreeHead the verified (for consistency) LogTreeHead that was used for successful verification (of inclusion) of the supplied proof. This may be older than the LogTreeHead passed in.
	 */
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

	/**
	 * Utility method for auditors that wish to audit the full content of a log, as well as the log operation.
	 * This method will retrieve all entries in batch from the log, and ensure that the root hash in head can be confirmed to accurately represent the contents
	 * of all of the log entries. If prev is not null, then additionally it is proven that the root hash in head is consistent with the root hash in prev.
	 * @param LogTreeHead $prev a previous LogTreeHead representing the set of entries that have been previously audited. To avoid potentially masking client tree head storage issues, it is an error to pass NULL. To indicate this is has not previously been audited, pass {@link LogTreeHead#ZeroLogTreeHead},
	 * @param LogTreeHead $head the LogTreeHead up to which we wish to audit the log. Upon successful completion the caller should persist this for a future iteration.
	 * @param mixed $auditor caller must implement auditLogEntry(int, *Entry) which is called sequentially for each index / log entry as it is encountered.
	 * @param mixed $factory the type of entry to return, usually one of new RawDataEntryFactory(), new JsonEntryFactory() or new RedactedJsonEntryFactory().
	 */
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

/**
 * Calculate the Merkle Tree Leaf Hash for an object (HASH(chr(0) || b)).
 * @param string $b the input to the leaf hash
 * @return string the leaf hash.
 */
function leaf_merkle_tree_hash($b) {
	return hash("sha256", chr(0) . $b, true);
}

/**
 * Calculate the Merkle Tree Node Hash for an existing left and right hash (HASH(chr(1) || l || r)).
 * @param string $l the left node hash.
 * @param string $r the right node hash.
 * @return string the node hash for the combination.
 */
function node_merkle_tree_hash($l, $r) {
	return hash("sha256", chr(1) . $l . $r, true);
}

/**
 * @ignore
 */
function calc_k($n) {
	$k = 1;
	while (($k << 1) < $n) {
		$k <<= 1;
	}
	return $k;
}

/**
 * @ignore
 */
function is_pow_2($n) {
	return calc_k($n + 1) == $n;
}

/**
 * Create the path in a sparse merkle tree for a given key. ie a boolean array representing
 * the big-endian index of the the hash of the key.
 * @param string $key the key
 * @return array[] a length 256 array of booleans representing left (false) and right (true) path in the Sparse Merkle Tree.
 */
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

/**
 * Generate the set of 257 default values for every level in a sparse Merkle Tree.
 * @return string[] array of length 257 default values.
 */
function generate_map_default_leaf_values() {
	$rv = array_fill(0, 257, null);
	$rv[256] = leaf_merkle_tree_hash("");
	for ($i = 255; $i >= 0; $i--) {
		$rv[$i] = node_merkle_tree_hash($rv[$i+1], $rv[$i+1]);
	}
	return $rv;
}

/**
 * @ignore
 */
$DEFAULT_LEAF_VALUES = generate_map_default_leaf_values();
?>
