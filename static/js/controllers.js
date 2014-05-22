var searchApp = angular.module('searchApp', ["ngResource"]);

searchApp.controller('searchCtrl', function ($scope, $resource) {
	$scope.doSearch = function(query) {
	var beerSearch = $resource("/api/untappd/noauth/search/beer", {});
	beerSearch.get({"q": query}).$promise.then(function(beers) {
		console.log(beers);
		$scope.beers = beers;
	})};

	$scope.query = "PBR"
});
