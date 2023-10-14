<?php

class JsonRPC
{
    private $conn;

    function __construct($host, $port)
    {
        $this->conn = fsockopen($host, $port, $errno, $errstr, 3);
        if (!$this->conn) {
            return false;
        }
    }

    public function Call($method, $params)
    {
        if (!$this->conn) {
            return false;
        }
        $err = fwrite($this->conn, json_encode(array(
                'method' => $method,
                'params' => array($params),
                'id' => 0,
            )) . "\n");

        if ($err === false) {
            return false;
        }
        stream_set_timeout($this->conn, 0, 3000);
        $line = fgets($this->conn);
        if ($line === false) {
            return NULL;
        }
        return json_decode($line, true);
    }
}

$client = new JsonRPC("127.0.0.1", 50001);

$r = $client->Call("GMSM2.Sign", array(
    "pri" => "e4b377d22205ec3d3e349584db812edc992319a41331abb2dd18089d6ad9310",
    "pub" => "90601ea80f199401b0103845c1a59a6bc4e521118ec421c5010f19e2e5c4fd7582c0f998507afeba895bfe48f27f5749ceea06ba7a2e55526907580413308c7b",
    'data' => base64_encode("123456")
));
var_dump('对123456签名');
var_dump($r);

$r = $client->Call("GMSM2.Verify", array(
    "pri" => "1e4b377d22205ec3d3e349584db812edc992319a41331abb2dd18089d6ad9310",
    "pub" => "90601ea80f199401b0103845c1a59a6bc4e521118ec421c5010f19e2e5c4fd7582c0f998507afeba895bfe48f27f5749ceea06ba7a2e55526907580413308c7b",
    'sig' => $r['result']['data'],
    "data" => base64_encode("123456")
));
var_dump('对123456验证签名');
var_dump($r);

$r = $client->Call("GMSM2.Encrypt", array(
    "pri" => "8e4b377d22205ec3d3e349584db812edc992319a41331abb2dd18089d6ad9310",
    "pub" => "90601ea80f199401b0103845c1a59a6bc4e521118ec421c5010f19e2e5c4fd7582c0f998507afeba895bfe48f27f5749ceea06ba7a2e55526907580413308c7b",
    'data' => base64_encode("123456")
));
var_dump('对123456加密');
var_dump($r);

$r = $client->Call("GMSM2.Decrypt", array(
    "pri" => "8e4b377d22205ec3d3e349584db812edc992319a41331abb2dd18089d6ad9310",
    "pub" => "90601ea80f199401b0103845c1a59a6bc4e521118ec421c5010f19e2e5c4fd7582c0f998507afeba895bfe48f27f5749ceea06ba7a2e55526907580413308c7b",
    'data' => $r['result']['data']
));
var_dump('对123456加密后的密文解密');
var_dump($r);
var_dump(base64_decode($r['result']['data']));
