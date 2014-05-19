var searchApp = angular.module('searchApp', ["ngResource"]);

searchApp.controller('searchCtrl', function ($scope, $resource) {
	$scope.doSearch = function(query) {
	var adminConfig = $resource("/api/admin/config", {})
	var beerSearch = $resource("http://api.untappd.com/v4/search/beer", {})
	adminConfig.get({}).$promise.then(function(cfg) {
		searchArgs = {
			"q": query,
			client_id: cfg.ClientId,
			client_secret:cfg.ClientSecret
		}
		beerSearch.get(searchArgs).$promise.then(function(b) {
			$scope.beers = b;
		});
	})}
	$scope.query = "PBR"
});
