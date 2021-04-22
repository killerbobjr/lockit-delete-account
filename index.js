var	path = require('path'),
	events = require('events'),
	util = require('util'),
	express = require('express'),
	pwd = require('couch-pwd'),
	utils = require('lockit-utils');


/**
 * DeleteAccount constructor function.
 *
 * @constructor
 * @param {Object} config
 * @param {Object} adapter
 */
var DeleteAccount = module.exports = function(cfg, adapter)
{
	if(!(this instanceof DeleteAccount))
	{
		return new DeleteAccount(cfg, adapter);
	}

	this.config = cfg;
	this.adapter = adapter;
	var	config = this.config;

	// call super constructor function
	events.EventEmitter.call(this);

	// set default route
	var route = config.deleteAccount.route || '/deleteaccount';

	// add prefix when rest is active
	if(config.rest) 
	{
		route = '/' + config.rest.route + route;
	}

	/**
	 * Routes
	 */
	var router = express.Router();
	router.get(route, utils.restrict(config), this.getDelete.bind(this));
	router.post(route, utils.restrict(config), this.postDelete.bind(this));
	this.router = router;

};

util.inherits(DeleteAccount, events.EventEmitter);



/**
 * Response handler
 *
 * @param {Object} err
 * @param {String} view
 * @param {Object} user
 * @param {Object} req
 * @param {Object} res
 * @param {Function} next
 */
DeleteAccount.prototype.sendResponse = function(err, view, user, json, req, res, next)
{
	var	config = this.config;

	this.emit((config.deleteAccount.eventMessage || 'DeleteAccount'), err, view, user, res);
	
	if(config.deleteAccount.handleResponse)
	{
		// do not handle the route when REST is active
		if(config.rest || req.query.rest)
		{
			if(err)
			{
				// Duplicate to make it easy for REST
				// response handlers to detect
				if(!err.error)
				{
					err.error = err.message;
				}
				res.json(err);
			}
			else
			{
				if(redirect)
				{
					json.redirect = redirect;
				}
				res.json(json);
			}
		}
		else
		{
			// custom or built-in view
			var	resp = {
					title: config.deleteAccount.title || 'Delete Account',
					basedir: req.app.get('views')
				};
				
			if(err)
			{
				resp.error = err.message;
			}
			
			if(view)
			{
				var	file = path.resolve(path.normalize(resp.basedir + '/' + view));
				res.render(view, Object.assign(resp, json));
			}
			else
			{
				res.status(404).send('<p>No file has been set in the configuration for this view path.</p><p>Please make sure you set a valid file for the "deleteAccount.views" configuration.</p>');
			}
		}
	}
	else
	{
		next(err);
	}
};



/**
 * GET /delete-account.
 *
 * @param {Object} req
 * @param {Object} res
 * @param {Function} next
 */
DeleteAccount.prototype.getDelete = function(req, res, next)
{
	var config = this.config;
	this.sendResponse(undefined, config.deleteAccount.views.remove, undefined, {view:'remove'}, req, res, next);
};



/**
 * POST /delete-account.
 *
 * @param {Object} req
 * @param {Object} res
 * @param {Function} next
 */
DeleteAccount.prototype.postDelete = function(req, res, next)
{
	var	config = this.config,
		adapter = this.adapter,
		that = this,
		email = req.body.email,	// verify input fields
		phrase = req.body.phrase,
		password = req.body.password,
		error = null;

	// check for valid inputs and valid session
	if(!email || !phrase || !password)
	{
		error = 'All fields are required';
	}
	else if(phrase !== 'DELETE ACCOUNT')
	{
		error = 'The phrase is incorrect';
	}
	else if(req.user !== undefined && req.user.email !== undefined && req.user.email !== email)
	{
		error = 'Please enter your email address';
	}

	if(error)
	{
		that.sendResponse({message:error}, config.deleteAccount.views.remove, req.user, {view:'remove'}, req, res, next);
	}
	else
	{
		// Custom for our app
		var basequery = {};
		if(res.locals && res.locals.basequery)
		{
			basequery = res.locals.basequery;
		}

		// get user from db
		adapter.find('email', email, function(err, user)
			{
				if(err)
				{
					next(err);
				}
				else
				{
					// no need to check if user exists in db since we are already checking against current session

					// if user comes from couchdb it has an 'iterations' key
					if(user.iterations)
					{
						pwd.iterations(user.iterations);
					}
					
					// verify user password
					pwd.hash(password, user.salt, function(err, hash)
						{
							if(err)
							{
								next(err);
							}
							else
							{
								// compare hash with hash from db
								if(hash !== user.derived_key)
								{
									that.sendResponse({message:'The password is incorrect'}, config.deleteAccount.views.remove, user, {view:'remove'}, req, res, next);
								}
								else
								{
									// invalidate user in db
									user.accountLocked = true;
									user.accountInvalid = true;
									delete user.email;
									adapter.update(user, function(err)
										{
											if(err)
											{
												next(err);
											}
											else
											{
												// kill session
												utils.destroy(req, function()
													{
														if(config.deleteAccount.completionRoute)
														{
															if(typeof config.deleteAccount.completionRoute === 'function')
															{
																config.deleteAccount.completionRoute(user, req, res, function(err, req, res)
																	{
																		if(err)
																		{
																			next(err);
																		}
																		else
																		{
																			that.sendResponse(undefined, req.query.redirect?undefined:config.deleteAccount.views.removed, user, {view:'removed'}, req.query.redirect, req, res, next);
																		}
																	});
															}
															else
															{
																that.sendResponse(undefined, undefined, user, {view:'removed'}, config.deleteAccount.completionRoute, req, res, next);
															}
														}
														else
														{
															that.sendResponse(undefined, config.deleteAccount.views.removed, user, {view:'removed'}, undefined, req, res, next);
														}
														
													});
											}
										});
								}
							}
						});
				}
			}, basequery);
	}
};