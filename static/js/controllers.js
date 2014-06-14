var cellarApp = angular.module('cellarApp',
	["ngRoute", "ngResource", "ui.bootstrap", "ngGrid"]);

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
      when('/admin', {
        templateUrl: 'partials/admin.html',
        controller: 'adminCtrl'
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
			$scope.isAdmin = u.data.is_admin
		} else if (u.status == 404) {
			$scope.authOperation = "/login";
			$scope.authText = "Login";
			$scope.isAdmin = false
		}
	})
}]);

cellarApp.controller('searchCtrl', ["$scope", "$resource", "security", function ($scope, $resource, security) {
	$scope.doSearch = function(query) {
	var beerSearch = $resource("/api/untappd/search/beer", {});
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

	$scope.cellarData = []
	$scope.gridOptions = {
		data: 'cellarData',
		columnDefs: [
		{field: "qty", width: "5%" },
		{field: "beer", width: "30%" },
		{field: "brewery", width: "30%" },
		{field: "notes", width: "**" }
		]
	};

	var cellarGetter = $resource("/api/user/me/cellar/default", {});
	cellarGetter.get({}).$promise.then(function(j) {
		angular.forEach(j.response.items, function(value, key) {
			$scope.cellarData.push({
				"qty": value.quantity,
				"beer": value.beer.beer_name,
				"brewery": value.brewery.brewery_name,
				"notes": value.notes});
		});
	}, function(msg){
		console.error(msg);
	});
}]);

cellarApp.controller('adminCtrl', ["$scope", "$resource", "security", function ($scope, $resource, security) {
}]);