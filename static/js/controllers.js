var cellarApp = angular.module('cellarApp',
	["ngRoute", "ngResource", "ui.bootstrap"]);

cellarApp.factory('security',
	['$http', function($http) {
		var service = {
			getCurrentUser: function() {
				var promise = $http.get('/api/user/me').then(function (response) {
					return response.data;
				});
				return promise;
			}
		};
		return service;
	}]
);

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

cellarApp.controller('searchCtrl', ["$scope", "$resource", "security", function ($scope, $resource, security) {
	$scope.doSearch = function(query) {
	var beerSearch = $resource("/api/untappd/noauth/search/beer", {});
	beerSearch.get({"q": query}).$promise.then(function(beers) {
		$scope.beers = beers;
	})};

	security.getCurrentUser().then(function(u) {
		$scope.currentUser = u
	})

	$scope.query = "PBR";
}]);

cellarApp.controller('cellarCtrl', function ($scope) {
    $scope.message = 'UNDER CONSTRUCTION';
});
