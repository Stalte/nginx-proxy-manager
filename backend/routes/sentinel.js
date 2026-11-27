import express from "express";
import internalSentinel from "../internal/sentinel.js";
import jwtdecode from "../lib/express/jwt-decode.js";
import apiValidator from "../lib/validator/api.js";
import validator from "../lib/validator/index.js";
import { debug, express as logger } from "../logger.js";
import { getValidationSchema } from "../schema/index.js";

const router = express.Router({
	caseSensitive: true,
	strict: true,
	mergeParams: true,
});

const handle = (fn) => async (req, res, next) => {
	try {
		await fn(req, res);
	} catch (err) {
		debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
		next(err);
	}
};

const idParam = async (value) => {
	const data = await validator(
		{
			required: ["id"],
			additionalProperties: false,
			properties: { id: { $ref: "common#/properties/id" } },
		},
		{ id: value },
	);
	return Number.parseInt(data.id, 10);
};

/**
 * GET /api/sentinel/status
 */
router
	.route("/status")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.get(
		handle(async (_req, res) => {
			res.status(200).send(await internalSentinel.status(res.locals.access));
		}),
	);

/**
 * /api/sentinel/rules
 */
router
	.route("/rules")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.get(
		handle(async (_req, res) => {
			res.status(200).send(await internalSentinel.getRules(res.locals.access));
		}),
	)
	.post(
		handle(async (req, res) => {
			const payload = await apiValidator(getValidationSchema("/sentinel/rules", "post"), req.body);
			res.status(201).send(await internalSentinel.createRule(res.locals.access, payload));
		}),
	);

/**
 * PUT /api/sentinel/rules/order
 */
router
	.route("/rules/order")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.put(
		handle(async (req, res) => {
			const payload = await apiValidator(getValidationSchema("/sentinel/rules/order", "put"), req.body);
			res.status(200).send(await internalSentinel.orderRules(res.locals.access, payload.ids));
		}),
	);

/**
 * /api/sentinel/rules/123
 */
router
	.route("/rules/:rule_id")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.get(
		handle(async (req, res) => {
			const id = await idParam(req.params.rule_id);
			res.status(200).send(await internalSentinel.getRule(res.locals.access, id));
		}),
	)
	.put(
		handle(async (req, res) => {
			const id = await idParam(req.params.rule_id);
			const payload = await apiValidator(getValidationSchema("/sentinel/rules/{ruleID}", "put"), req.body);
			res.status(200).send(await internalSentinel.updateRule(res.locals.access, id, payload));
		}),
	)
	.delete(
		handle(async (req, res) => {
			const id = await idParam(req.params.rule_id);
			res.status(200).send(await internalSentinel.deleteRule(res.locals.access, id));
		}),
	);

/**
 * /api/sentinel/lists
 */
router
	.route("/lists")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.get(
		handle(async (_req, res) => {
			res.status(200).send(await internalSentinel.getLists(res.locals.access));
		}),
	)
	.post(
		handle(async (req, res) => {
			const payload = await apiValidator(getValidationSchema("/sentinel/lists", "post"), req.body);
			res.status(201).send(await internalSentinel.createList(res.locals.access, payload));
		}),
	);

/**
 * /api/sentinel/lists/123
 */
router
	.route("/lists/:list_id")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.get(
		handle(async (req, res) => {
			const id = await idParam(req.params.list_id);
			res.status(200).send(await internalSentinel.getList(res.locals.access, id));
		}),
	)
	.put(
		handle(async (req, res) => {
			const id = await idParam(req.params.list_id);
			const payload = await apiValidator(getValidationSchema("/sentinel/lists/{listID}", "put"), req.body);
			res.status(200).send(await internalSentinel.updateList(res.locals.access, id, payload));
		}),
	)
	.delete(
		handle(async (req, res) => {
			const id = await idParam(req.params.list_id);
			res.status(200).send(await internalSentinel.deleteList(res.locals.access, id));
		}),
	);

/**
 * POST /api/sentinel/lists/123/refresh
 */
router
	.route("/lists/:list_id/refresh")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.post(
		handle(async (req, res) => {
			const id = await idParam(req.params.list_id);
			res.status(200).send(await internalSentinel.refreshList(res.locals.access, id));
		}),
	);

/**
 * GET /api/sentinel/under-attack
 */
router
	.route("/under-attack")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.get(
		handle(async (_req, res) => {
			res.status(200).send(await internalSentinel.getUnderAttack(res.locals.access));
		}),
	);

/**
 * GET /api/sentinel/under-attack/events
 */
router
	.route("/under-attack/events")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.get(
		handle(async (_req, res) => {
			res.status(200).send(await internalSentinel.underAttackEvents(res.locals.access));
		}),
	);

/**
 * PUT /api/sentinel/under-attack/123
 */
router
	.route("/under-attack/:host_id")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.put(
		handle(async (req, res) => {
			const id = await idParam(req.params.host_id);
			const payload = await apiValidator(getValidationSchema("/sentinel/under-attack/{hostID}", "put"), req.body);
			res.status(200).send(await internalSentinel.setUnderAttack(res.locals.access, id, payload));
		}),
	);

/**
 * POST /api/sentinel/under-attack/123/deactivate
 */
router
	.route("/under-attack/:host_id/deactivate")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.post(
		handle(async (req, res) => {
			const id = await idParam(req.params.host_id);
			res.status(200).send(await internalSentinel.deactivateUnderAttack(res.locals.access, id));
		}),
	);

/**
 * /api/sentinel/alerts
 */
router
	.route("/alerts")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.get(
		handle(async (_req, res) => {
			res.status(200).send(await internalSentinel.getAlerts(res.locals.access));
		}),
	)
	.put(
		handle(async (req, res) => {
			const payload = await apiValidator(getValidationSchema("/sentinel/alerts", "put"), req.body);
			res.status(200).send(await internalSentinel.setAlerts(res.locals.access, payload));
		}),
	);

/**
 * POST /api/sentinel/alerts/test
 */
router
	.route("/alerts/test")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.post(
		handle(async (_req, res) => {
			res.status(200).send(await internalSentinel.testAlert(res.locals.access));
		}),
	);

export default router;
