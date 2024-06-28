import Joi from "joi";

const userSchema = Joi.object({
	email: Joi.string().email(),
	name: Joi.string().trim().min(3).max(20),
	password: Joi.string().min(8).max(20),
}).or("email", "name", "password");

const validateUser = (userData) => {
	return userSchema.validate(userData);
};

export { validateUser };
