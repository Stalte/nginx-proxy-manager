import { migrate as logger } from "../logger.js";

const migrateName = "sentinel";

/**
 * Migrate
 *
 * Sentinel security rules and the IP / User-Agent lists they reference.
 *
 * @param   {Object} knex
 * @returns {Promise}
 */
const up = (knex) => {
	logger.info(`[${migrateName}] Migrating Up...`);

	return knex.schema
		.createTable("sentinel_list", (table) => {
			table.increments().primary();
			table.dateTime("created_on").notNull();
			table.dateTime("modified_on").notNull();
			table.integer("owner_user_id").notNull().unsigned();
			table.integer("is_deleted").notNull().unsigned().defaultTo(0);
			table.string("name", 100).notNull();
			table.string("description", 500).notNull().defaultTo("");
			// ip | user_agent
			table.string("kind", 20).notNull().defaultTo("ip");
			// Lists fed from a URL: refreshed every refresh_s seconds
			table.string("source_url", 2048).notNull().defaultTo("");
			table.integer("refresh_s").notNull().unsigned().defaultTo(3600);
			// Entries of lists edited by hand, and of User-Agent feeds
			table.json("items").notNull();
			// IP feeds keep their entries in a range file (/data/sentinel/lists/<sha256>.bin)
			table.string("data_hash", 64).notNull().defaultTo("");
			table.integer("item_count").notNull().unsigned().defaultTo(0);
			table.dateTime("fetched_on").nullable();
			table.dateTime("changed_on").nullable();
			table.string("fetch_error", 500).notNull().defaultTo("");
			table.json("meta").notNull();
		})
		.then(() => {
			logger.info(`[${migrateName}] sentinel_list Table created`);
			return knex.schema.createTable("sentinel_rule", (table) => {
				table.increments().primary();
				table.dateTime("created_on").notNull();
				table.dateTime("modified_on").notNull();
				table.integer("owner_user_id").notNull().unsigned();
				table.integer("is_deleted").notNull().unsigned().defaultTo(0);
				table.integer("enabled").notNull().unsigned().defaultTo(1);
				table.integer("position").notNull().defaultTo(0);
				table.string("name", 100).notNull();
				table.string("description", 500).notNull().defaultTo("");
				// block | allow | log (challenge comes with the browser challenge)
				table.string("action", 20).notNull();
				table.integer("status_code").notNull().unsigned().defaultTo(403);
				// all | hosts
				table.string("scope", 10).notNull().defaultTo("all");
				table.json("host_ids").notNull();
				// { groups: [[condition, ...], ...] }: any group whose conditions all match
				table.json("expression").notNull();
				table.json("meta").notNull();
			});
		})
		.then(() => {
			logger.info(`[${migrateName}] sentinel_rule Table created`);
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
		.dropTableIfExists("sentinel_rule")
		.then(() => knex.schema.dropTableIfExists("sentinel_list"))
		.then(() => {
			logger.info(`[${migrateName}] sentinel tables dropped`);
		});
};

export { down, up };
