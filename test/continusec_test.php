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


require "src/continusec.php";

/**
 * @ignore
 */
class Counter {
	/**
	 * @ignore
	 */
	private $count;

	/**
	 * @ignore
	 */
	function Counter() {
		$this->count = 0;
	}

	/**
	 * @ignore
	 */
	function auditLogEntry($idx, $entry) {
		$entry->getData();
		$this->count++;
	}

	/**
	 * @ignore
	 */
	function getCount() {
		return $this->count;
	}
}

/**
 * @ignore
 */
function test_client() {
	$client = new ContinusecClient("7981306761429961588", "c9fc80d4e19ddbf01a4e6b5277a29e1bffa88fe047af9d0b9b36de536f85c2c6", "http://localhost:8080");
	$log = $client->getVerifiableLog("newtestlog");
	try {
		$log->getTreeHead(0);
		throw new Exception();
	} catch (ObjectNotFoundException $e) {
		// good
	}

	$client = new ContinusecClient("7981306761429961588", "wrongcred", "http://localhost:8080");
	$log = $client->getVerifiableLog("newtestlog");
	try {
		$log->getTreeHead(0);
		throw new Exception();
	} catch (UnauthorizedAccessException $e) {
		// good
	}

	$client = new ContinusecClient("wrongaccount", "wrongcred", "http://localhost:8080");
	$log = $client->getVerifiableLog("newtestlog");
	try {
		$log->getTreeHead(0);
		throw new Exception();
	} catch (ObjectNotFoundException $e) {
		// good
	}

	$client = new ContinusecClient("7981306761429961588", "c9fc80d4e19ddbf01a4e6b5277a29e1bffa88fe047af9d0b9b36de536f85c2c6", "http://localhost:8080");
	$log = $client->getVerifiableLog("newtestlog");
	$log->create();
	try {
		$log->create();
		throw new Exception();
	} catch (ObjectConflictException $e) {
		// good
	}


	$log->addEntry(new RawDataEntry("foo"));
	$log->addEntry(new JsonEntry("{\"name\":\"adam\",\"ssn\":123.45}"));
	$log->addEntry(new RedactableJsonEntry("{\"name\":\"adam\",\"ssn\":123.45}"));

	$log->blockUntilPresent($log->addEntry(new RawDataEntry("foo"))->getLeafHash());

	$head = $log->getTreeHead(0);
	if ($head->getTreeSize() != 3) {
		throw new Exception();
	}

	for ($i = 0; $i < 100; $i++) {
		$log->addEntry(new RawDataEntry("foo-".$i));
	}

	$head103 = $log->fetchVerifiedTreeHead($head);
	if ($head103->getTreeSize() != 103) {
		throw new Exception();
	}

	try {
		$rde = new RawDataEntry("foo27");
		$log->getInclusionProof($head103->getTreeSize(), $rde->getLeafHash());
		throw new Exception();
	} catch (ObjectNotFoundException $e) {
		// good
	}

	$rde = new RawDataEntry("foo-27");
	$inclProof = $log->getInclusionProof($head103->getTreeSize(), $rde->getLeafHash());
	$inclProof->verify($head103);

	try {
		$inclProof->verify($head);
		throw new Exception();
	} catch (VerificationFailedException $e) {
		// good
	}

	$head50 = $log->getTreeHead(50);
	if ($head50->getTreeSize() != 50) {
		throw new Exception();
	}

	$cons = $log->getConsistencyProof($head50->getTreeSize(), $head103->getTreeSize());
	$cons->verify($head50, $head103);
	try {
		$cons->verify($head, $head103);
		throw new Exception();
	} catch (VerificationFailedException $e) {
		// good
	}

	$rde = new RawDataEntry("foo");
	$inclProof = $log->getInclusionProof(10, $rde->getLeafHash());
	$h10 = $log->verifySuppliedInclusionProof($head103, $inclProof);

	$c = new Counter();
	$log->auditLogEntries(new LogTreeHead(0, null), $head103, new RawDataEntryFactory(), $c);
	if ($c->getCount() != 103) {
		throw new Exception();
	}

	$h1 = $log->getTreeHead(1);
	$c = new Counter();
	try {
		$log->auditLogEntries($h1, $head103, new JsonEntryFactory(), $c);
	} catch (NotAllEntriesReturnedException $e) {
		// good
	}
	if ($c->getCount() != 0) {
		throw new Exception();
	}

	$h3 = $log->getTreeHead(3);
	$c = new Counter();
	$log->auditLogEntries($h1, $h3, new JsonEntryFactory(), $c);
	if ($c->getCount() != 2) {
		throw new Exception();
	}

	$c = new Counter();
	$log->auditLogEntries($head50, $head103, new RawDataEntryFactory(), $c);
	if ($c->getCount() != 53) {
		throw new Exception();
	}

	$je = new JsonEntry("{    \"ssn\":  123.4500 ,   \"name\" :  \"adam\"}");
	$inclProof = $log->getInclusionProof($head103->getTreeSize(), $je->getLeafHash());
	$inclProof->verify($head103);

	$redEnt = $log->getEntry(2, new RedactedJsonEntryFactory());
	$dd = $redEnt->getData();
	if (strpos($dd, "ssn") !== false) {
		throw new Exception();
	}
	if (strpos($dd, "adam") === false) {
		throw new Exception();
	}

	$inclProof = $log->getInclusionProof($head103->getTreeSize(), $redEnt->getLeafHash());
	$inclProof->verify($head103);

	$client = new ContinusecClient("7981306761429961588", "allseeing", "http://localhost:8080");
	$log = $client->getVerifiableLog("newtestlog");

	$redEnt = $log->getEntry(2, new RedactedJsonEntryFactory());
	$dd = $redEnt->getData();
	if (strpos($dd, "123.45") === false) {
		throw new Exception();
	}
	if (strpos($dd, "adam") === false) {
		throw new Exception();
	}

	$inclProof = $log->getInclusionProof($head103->getTreeSize(), $redEnt->getLeafHash());
	$inclProof->verify($head103);
}

/**
 * @ignore
 */
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

test_client();
object_hash_test("../objecthash/common_json.test");
?>