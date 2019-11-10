const
	bcrypt = require(`bcrypt`),
	makeSid = require(`sid`);

module.exports = class {
	constructor(users, sids) {
		this.users = users;
		this.sids = sids;
	}

	get() {
		return async (req, _, next) => {
			const sid = req.cookies.SID;
			if (sid) {
				const
					{users, sids} = this,
					sidObj = await sids.findOne({_id: sid});

				if (sidObj) {
					sids.updateOne(sidObj, {$currentDate: {assigned: true}});
					req.user = await users.findOne({_id: sidObj.user_id});
				} else req.user = null;
			}

			next();
		};
	}

	//async create(fields) {
	//	fields.password = await bcrypt.hash(fields.password, 10);
	//	return this.users.insertOne(fields);
	//}

	create(pass, fail, extra) {
		return async (req, res) => {
			req.body.password = await bcrypt.hash(req.body.password, 10);
			try {
				await this.users.insertOne({...req.body, ...extra});
				await this.session(res, req.body._id);
				res.redirect(pass);
			} catch {
				res.redirect(fail);
			}
		};
	}

	//async auth({_id, password} = {}) {
	//	const potentialUser = await this.users.findOne({_id});
	//	if (potentialUser) return bcrypt.compare(password, potentialUser.password);
	//	else return false;
	//}

	auth(pass, fail) {
		return async (req, res) => {
			const
				{_id, password} = req.body,
				potentialUser = await this.users.findOne({_id});

			if (potentialUser && await bcrypt.compare(password, potentialUser.password)) {
				await this.session(res, _id);
				res.redirect(pass);
			} else res.redirect(fail);
		};
	}

	async session(res, _id, {
		path = `/`,
		maxAge = 30 * 86400,
	} = {}) {
		if (await this.users.findOne({_id})) {
			const sid = makeSid(20);
			try {
				await this.sids.insertOne({
					_id: sid,
					user_id: _id,
					assigned: new Date(),
				});

				res.set(`Set-Cookie`, `SID=${sid}; path=${path}; Max-Age=${maxAge}`);
				return true;
			} catch (error) {
				if (error.code === 11000)
					console.log(`cookie collision`);
			}
		}
	}
};
