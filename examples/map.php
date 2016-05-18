<?php

// Create client
$client = new ContinusecClient("your account number", "your secret key");

// Get pointer to map
$map = $client->getVerifiableMap("testmap");

// Once we have a handle to the map, to create it before first use:
$map->create();

// To add entries to the map (calling each of these adds an entry to the mutation log):
$map->set("foo", new RawDataEntry("bar"));
$map->set("fiz", new JsonEntry("{\"name\":\"adam\",\"ssn\":123.45}"));
$map->set("fiz1", new RedactableJsonEntry("{\"name\":\"adam\",\"ssn\":123.45}"));
$map->delete("foo");

// To block until a mutation has been sequenced in the mutation log (useful for testing):
$ae = $map->set("fiz4", new RawDataEntry("foz4"));
$lth = $map->getMutationLog()->blockUntilPresent($aer);

// To further block until a specific mutation has been sequenced in the mutation log, and reflected back into the map of equivalent size (useful for testing):
$mth = $map->blockUntilSize($lth->getTreeSize());

// To get the latest MapTreeState from a map, verify the consistency of the underlying mutation log, and inclusion in the tree head log:
$prev = loadPrevState();
$head = $map->getVerifiedLatestMapState($prev);
if ($head->getTreeSize() > $prev->getTreeSize()) {
    savePrevState($head);
}

// To get a value from the map, and prove its inclusion in the map root hash:
$entry = $map->getVerifiedValue("foo", $head, new RawDataEntryFactory());

?>
