import { migrate as logger } from "../logger.js";

const migrateName = "sentinel_bans";

/**
 * Migrate
 *
 * Sentinel automatic and manual bans, rate limit policies, and the per proxy host
 * "no automatic bans" switch.
 *
 * @param   {Object} knex
 * @returns {Promise}
 */
const up = (knex) => {
	logger.info(`[${migrateName}] Migrating Up...`);

	return knex.schema
		.createTable("sentinel_ban", (table) => {
			table.increments().primary();
			table.dateTime("created_on").notNull();
			table.dateTime("modified_on").notNull();
			// IPv4 address, or IPv6 /64 ("2001:db8:1:2::/64")
			table.string("ip", 64).notNull().unique();
			table.string("reason", 500).notNull().defaultTo("");
			// auto | manual
			table.string("source", 10).notNull().defaultTo("auto");
			// automatic bans of this client so far (escalation); kept after a ban ends
			table.integer("offenses").notNull().unsigned().defaultTo(1);
			// end of the ban, unix seconds (an integer compares the same on every
			// database engine); null: permanent
			table.bigInteger("expires_at").nullable();
		})
		.then(() => {
			logger.info(`[${migrateName}] sentinel_ban Table created`);
			return knex.schema.createTable("sentinel_rate_limit", (table) => {
				table.increments().primary();
				table.dateTime("created_on").notNull();
				table.dateTime("modified_on").notNull();
				table.integer("owner_user_id").notNull().unsigned();
				table.integer("is_deleted").notNull().unsigned().defaultTo(0);
				table.integer("enabled").notNull().unsigned().defaultTo(1);
				table.string("name", 100).notNull();
				table.integer("requests_per_second").notNull().unsigned().defaultTo(10);
				table.integer("burst").notNull().unsigned().defaultTo(20);
				table.integer("max_connections").notNull().unsigned().defaultTo(0);
				table.integer("status_code").notNull().unsigned().defaultTo(429);
				table.integer("dry_run").notNull().unsigned().defaultTo(0);
				table.json("exempt").notNull();
				table.json("host_ids").notNull();
			});
		})
		.then(() => {
			logger.info(`[${migrateName}] sentinel_rate_limit Table created`);
			return knex.schema.table("sentinel_host", (table) => {
				table.integer("no_autoban").notNull().unsigned().defaultTo(0);
			});
		})
		.then(() => {
			logger.info(`[${migrateName}] sentinel_host Table altered`);
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
		.dropTableIfExists("sentinel_ban")
		.then(() => knex.schema.dropTableIfExists("sentinel_rate_limit"))
		.then(() =>
			knex.schema.table("sentinel_host", (table) => {
				table.dropColumn("no_autoban");
			}),
		)
		.then(() => {
			logger.info(`[${migrateName}] Migrating Down Complete`);
		});
};

export { down, up };
