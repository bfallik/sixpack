var cellarApp = angular.module('cellarApp',
	["ngRoute", "ngResource", "ui.bootstrap"]);

cellarApp.config(
  function($routeProvider) {
    $routeProvider.
      when('/search', {
        templateUrl: 'partials/search.html',
        controller: 'searchCtrl'
    }).
      when('/cellar', {
        templateUrl: 'partials/cellar.html',
        controller: 'cellarCtrl'
      }).
      otherwise({
        redirectTo: '/search'
      })
  }
);

cellarApp.controller('searchCtrl', function ($scope, $resource) {
	$scope.doSearch = function(query) {
	var beerSearch = $resource("/api/untappd/noauth/search/beer", {});
	beerSearch.get({"q": query}).$promise.then(function(beers) {
		$scope.beers = beers;
	})};

	$scope.query = "PBR"
});

cellarApp.controller('cellarCtrl', function ($scope) {
    $scope.message = 'UNDER CONSTRUCTION';
});
