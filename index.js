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

	this.config = cfg.deleteAccount;
	this.adapter = adapter;

	var	config = this.config;

	// call super constructor function
	events.EventEmitter.call(this);

	// set default route
	var route = config.route || '/deleteaccount';

	// add prefix when rest is active
	if(config.rest) 
	{
		route = '/' + config.rest + route;
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

	this.emit((config.eventmsg || config.route), err, view, user, res);
	
	if(config.handleResponse)
	{
		// do not handle the route when REST is active
		if(config.rest)
		{
			if(err)
			{
				res.status(403).json(err);
			}
			else
			{
				res.json(json);
			}
		}
		else
		{
			// custom or built-in view
			var	resp = {
					title: config.title || 'Delete Account',
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
	this.sendResponse(undefined, config.views.remove, undefined, {result:true}, req, res, next);
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
		that.sendResponse({message:error}, config.views.remove, req.user, {result:true}, req, res, next);
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
									that.sendResponse({message:'The password is incorrect'}, config.views.remove, user, {result:true}, req, res, next);
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
														that.sendResponse(undefined, config.views.removed, user, {result:true}, req, res, next);
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