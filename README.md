#php-client

This is the open-source (Apache 2 License) PHP client for Continusec Verifiable Data Structures API.

To use, simply take the `src/continusec.php` file and include it in your app.

Note that we require the php-intl package to be installed if you need objecthash verification to work correctly, and we also need the curl library installed (welcome any alternative suggestions especially those in the form of pull requests) if these are difficult to come by).

See the docs (https://www.continusec.com/static/php/apidocs/classes/ContinusecClient.html), starting with creating a new `ContinusecClient` to get started.

To test (requires the go-client, which stands up a mock HTTP server):

`php src/continusec_test.go`

To generate docs:

`php ~/Downloads/phpDocumentor.phar -d src -t target`

