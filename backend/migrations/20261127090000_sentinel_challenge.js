import { migrate as logger } from "../logger.js";

const migrateName = "sentinel_challenge";

/**
 * Migrate
 *
 * Sentinel browser challenge: challenge settings of security rules, and the
 * per proxy host "under attack" mode.
 *
 * @param   {Object} knex
 * @returns {Promise}
 */
const up = (knex) => {
	logger.info(`[${migrateName}] Migrating Up...`);

	return knex.schema
		.table("sentinel_rule", (table) => {
			// {mode, difficulty, ttl, bind} for action "challenge", otherwise null
			table.json("challenge").nullable();
		})
		.then(() => {
			logger.info(`[${migrateName}] sentinel_rule Table altered`);
			return knex.schema.createTable("sentinel_host", (table) => {
				table.increments().primary();
				table.dateTime("created_on").notNull();
				table.dateTime("modified_on").notNull();
				table.integer("proxy_host_id").notNull().unsigned().unique();
				// off | on | auto
				table.string("under_attack", 10).notNull().defaultTo("off");
				// {mode, difficulty, ttl, bind, rps, blocked_pct, window_s, duration_s}
				table.json("config").notNull();
			});
		})
		.then(() => {
			logger.info(`[${migrateName}] sentinel_host Table created`);
		});
};

/**
 * Undo Migrate
 *
 * @param   {Object} knex
 * @returns {Promise}
 */
const down = (knex) => {
	logger.info(`[${migrateName}] Migrating Down...`);

	return knex.schema
		.dropTableIfExists("sentinel_host")
		.then(() =>
			knex.schema.table("sentinel_rule", (table) => {
				table.dropColumn("challenge");
			}),
		)
		.then(() => {
			logger.info(`[${migrateName}] Migrating Down Complete`);
		});
};

export { down, up };
