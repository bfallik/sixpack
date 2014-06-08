var cellarApp = angular.module('cellarApp',
	["ngRoute", "ngResource", "ui.bootstrap"]);

cellarApp.factory('security',
	['$http', function($http) {
		var service = {
			getCurrentUser: function() {
				var promise = $http.get('/api/user/me').
				then(function (response) {
					return response;
				}, function (response) {
					return response;
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

cellarApp.controller('navBarCtrl', ["$scope", "security", function ($scope, security) {
	security.getCurrentUser().then(function(u) {
		$scope.currentUser = u
	})

	security.getCurrentUser().then(function(u) {
		if (u.status == 200) {
			$scope.authOperation = "/logout";
			$scope.authText = "Logout";
		} else if (u.status == 404) {
			$scope.authOperation = "/login";
			$scope.authText = "Login";
		}
	})
}]);

cellarApp.controller('searchCtrl', ["$scope", "$resource", "security", function ($scope, $resource, security) {
	$scope.doSearch = function(query) {
	var beerSearch = $resource("/api/untappd/noauth/search/beer", {});
	beerSearch.get({"q": query}).$promise.then(function(beers) {
		$scope.beers = beers;
	}, function(msg){
		console.error(msg);
	})};

	security.getCurrentUser().then(function(u) {
		$scope.currentUser = u.data
	})

	$scope.query = "PBR";
}]);

cellarApp.controller('cellarCtrl', ["$scope", "$resource", "security", function ($scope, $resource, security) {
	security.getCurrentUser().then(function(u) {
		$scope.currentUser = u.data
	})

	var cellarGetter = $resource("/json/cellar.json", {});
	cellarGetter.get({}).$promise.then(function(j) {
		$scope.cellar = j.response;
	}, function(msg){
		console.error(msg);
	});

}]);
