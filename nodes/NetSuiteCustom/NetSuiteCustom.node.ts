import { debuglog } from 'util';
import * as crypto from 'crypto';
import {
	IDataObject,
	IExecuteFunctions,
	IHttpRequestMethods,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
	JsonObject,
	NodeApiError,
} from 'n8n-workflow';

import {
	INetSuiteCredentials,
	INetSuiteOperationOptions,
	INetSuitePagedBody,
	INetSuiteRequestOptions,
	INetSuiteResponse,
	NetSuiteRequestType,
} from './NetSuiteCustom.node.types';

import {
	nodeDescription,
} from './NetSuiteCustom.node.options';

import { makeRequest } from '@fye/netsuite-rest-api';
import OAuth from 'oauth-1.0a';

import pLimit from 'p-limit';

const debug = debuglog('n8n-nodes-netsuite-custom');

const handleNetsuiteResponse = (fns: IExecuteFunctions, response: INetSuiteResponse) => {
	// debug(response);
	debug(`Netsuite response:`, response.statusCode, response.body);
	let body: JsonObject = {};
	const {
		title: webTitle = undefined,
		// code: restletCode = undefined,
		'o:errorCode': webCode,
		'o:errorDetails': webDetails,
		message: restletMessage = undefined,
	} = response.body;
	if (!(response.statusCode && response.statusCode >= 200 && response.statusCode < 400)) {
		let message = webTitle || restletMessage || webCode || response.statusText;
		if (webDetails && webDetails.length > 0) {
			message = webDetails[0].detail || message;
		}
		if (fns.continueOnFail() !== true) {
			// const code = webCode || restletCode;
			const error = new NodeApiError(fns.getNode(), response.body);
			error.message = message;
			throw error;
		} else {
			body = {
				error: message,
			};
		}
	} else {
		body = response.body;
		if ([ 'POST', 'PATCH', 'DELETE' ].includes(response.request.options.method)) {
			body = typeof body === 'object' ? response.body : {};
			if (response.headers['x-netsuite-propertyvalidation']) {
				body.propertyValidation = response.headers['x-netsuite-propertyvalidation'].split(',');
			}
			if (response.headers['x-n-operationid']) {
				body.operationId = response.headers['x-n-operationid'];
			}
			if (response.headers['x-netsuite-jobid']) {
				body.jobId = response.headers['x-netsuite-jobid'];
			}
			if (response.headers['location']) {
				body.links = [
					{
						rel: 'self',
						href: response.headers['location'],
					},
				];
				body.id = response.headers['location'].split('/').pop();
			}
			body.success = response.statusCode === 204;
		}
	}
	// debug(body);
	return { json: body };
};

const getConfig = (credentials: INetSuiteCredentials) => ({
	netsuiteApiHost: credentials.hostname,
	consumerKey: credentials.consumerKey,
	consumerSecret: credentials.consumerSecret,
	netsuiteAccountId: credentials.accountId,
	netsuiteTokenKey: credentials.tokenKey,
	netsuiteTokenSecret: credentials.tokenSecret,
	netsuiteQueryLimit: 1000,
});

// OAuth 1.0a helper for custom headers support
const getOAuthHeaders = (credentials: INetSuiteCredentials, requestData: { url: string; method: string }) => {
	const oauth = new OAuth({
		consumer: {
			key: credentials.consumerKey,
			secret: credentials.consumerSecret,
		},
		realm: credentials.accountId,
		signature_method: 'HMAC-SHA256',
		hash_function(baseString: string, key: string) {
			return crypto
				.createHmac('sha256', key)
				.update(baseString)
				.digest('base64');
		},
	});

	const token = {
		key: credentials.tokenKey,
		secret: credentials.tokenSecret,
	};

	return oauth.toHeader(oauth.authorize(requestData, token));
};

export class NetSuiteCustom implements INodeType {
	description: INodeTypeDescription = nodeDescription;

	static getRecordType({ fns, itemIndex }: INetSuiteOperationOptions): string {
		let recordType = fns.getNodeParameter('recordType', itemIndex) as string;
		if (recordType === 'custom') {
			recordType = fns.getNodeParameter('customRecordTypeScriptId', itemIndex) as string;
		}
		return recordType;
	}

	static async listRecords(options: INetSuiteOperationOptions): Promise<INodeExecutionData[]> {
		const { fns, credentials, itemIndex } = options;
		const nodeContext = fns.getContext('node');
		const apiVersion = fns.getNodeParameter('version', itemIndex) as string;
		const recordType = NetSuiteCustom.getRecordType(options);
		const returnAll = fns.getNodeParameter('returnAll', itemIndex) as boolean;
		const query = fns.getNodeParameter('query', itemIndex) as string;
		let limit = 100;
		let offset = 0;
		let hasMore = true;
		const method = 'GET';
		let nextUrl;
		const requestType = NetSuiteRequestType.Record;
		const params = new URLSearchParams();
		const returnData: INodeExecutionData[] = [];
		let prefix = query ? `?${query}` : '';
		if (returnAll !== true) {
			prefix = query ? `${prefix}&` : '?';
			limit = fns.getNodeParameter('limit', itemIndex) as number || limit;
			offset = fns.getNodeParameter('offset', itemIndex) as number || offset;
			params.set('limit', String(limit));
			params.set('offset', String(offset));
			prefix += params.toString();
		}
		const requestData: INetSuiteRequestOptions = {
			method,
			requestType,
			path: `services/rest/record/${apiVersion}/${recordType}${prefix}`,
		};
		nodeContext.hasMore = hasMore;
		nodeContext.count = limit;
		nodeContext.offset = offset;
		// debug('requestData', requestData);
		while ((returnAll || returnData.length < limit) && hasMore === true) {
			const response = await makeRequest(getConfig(credentials), requestData);
			const body: JsonObject = handleNetsuiteResponse(fns, response);
			const { hasMore: doContinue, items, links, offset, count, totalResults } = (body.json as INetSuitePagedBody);
			if (doContinue) {
				nextUrl = (links.find((link) => link.rel === 'next') || {}).href;
				requestData.nextUrl = nextUrl;
			}
			if (Array.isArray(items)) {
				for (const json of items) {
					if (returnAll || returnData.length < limit) {
						returnData.push({ json });
					}
				}
			}
			hasMore = doContinue && (returnAll || returnData.length < limit);
			nodeContext.hasMore = doContinue;
			nodeContext.count = count;
			nodeContext.offset = offset;
			nodeContext.totalResults = totalResults;
			if (requestData.nextUrl) {
				nodeContext.nextUrl = requestData.nextUrl;
			}
		}
		return returnData;
	}

	static async runSuiteQL(options: INetSuiteOperationOptions): Promise<INodeExecutionData[]> {
		const { fns, credentials, itemIndex } = options;
		const nodeContext = fns.getContext('node');
		const apiVersion = fns.getNodeParameter('version', itemIndex) as string;
		const returnAll = fns.getNodeParameter('returnAll', itemIndex) as boolean;
		const query = fns.getNodeParameter('query', itemIndex) as string;
		let limit = 1000;
		let offset = 0;
		let hasMore = true;
		const method = 'POST';
		let nextUrl;
		const requestType = NetSuiteRequestType.SuiteQL;
		const params = new URLSearchParams();
		const returnData: INodeExecutionData[] = [];
		const config = getConfig(credentials);
		let prefix = '?';
		if (returnAll !== true) {
			limit = fns.getNodeParameter('limit', itemIndex) as number || limit;
			offset = fns.getNodeParameter('offset', itemIndex) as number || offset;
			params.set('offset', String(offset));
		}
		params.set('limit', String(limit));
		config.netsuiteQueryLimit = limit;
		prefix += params.toString();
		const requestData: INetSuiteRequestOptions = {
			method,
			requestType,
			query,
			path: `services/rest/query/${apiVersion}/suiteql${prefix}`,
		};
		nodeContext.hasMore = hasMore;
		nodeContext.count = limit;
		nodeContext.offset = offset;
		debug('requestData', requestData);
		while ((returnAll || returnData.length < limit) && hasMore === true) {
			const response = await makeRequest(config, requestData);
			const body: JsonObject = handleNetsuiteResponse(fns, response);
			const { hasMore: doContinue, items, links, count, totalResults, offset } = (body.json as INetSuitePagedBody);
			if (doContinue) {
				nextUrl = (links.find((link) => link.rel === 'next') || {}).href;
				requestData.nextUrl = nextUrl;
			}
			if (Array.isArray(items)) {
				for (const json of items) {
					if (returnAll || returnData.length < limit) {
						returnData.push({ json });
					}
				}
			}
			hasMore = doContinue && (returnAll || returnData.length < limit);
			nodeContext.hasMore = doContinue;
			nodeContext.count = count;
			nodeContext.offset = offset;
			nodeContext.totalResults = totalResults;
			if (requestData.nextUrl) {
				nodeContext.nextUrl = requestData.nextUrl;
			}
		}
		return returnData;
	}

	static async getRecord(options: INetSuiteOperationOptions): Promise<INodeExecutionData> {
		const { item, fns, credentials, itemIndex } = options;
		const params = new URLSearchParams();
		const expandSubResources = fns.getNodeParameter('expandSubResources', itemIndex) as boolean;
		const simpleEnumFormat = fns.getNodeParameter('simpleEnumFormat', itemIndex) as boolean;
		const apiVersion = fns.getNodeParameter('version', itemIndex) as string;
		const recordType = NetSuiteCustom.getRecordType(options);
		const internalId = fns.getNodeParameter('internalId', itemIndex) as string;
		if (expandSubResources) {
			params.append('expandSubResources', 'true');
		}
		if (simpleEnumFormat) {
			params.append('simpleEnumFormat', 'true');
		}
		const q = params.toString();
		const requestData = {
			method: 'GET',
			requestType: NetSuiteRequestType.Record,
			path: `services/rest/record/${apiVersion}/${recordType}/${internalId}${q ? `?${q}` : ''}`,
		};
		const response = await makeRequest(getConfig(credentials), requestData);
		if (item) response.body.orderNo = item.json.orderNo;
		return handleNetsuiteResponse(fns, response);
	}

	static async removeRecord(options: INetSuiteOperationOptions): Promise<INodeExecutionData> {
		const { fns, credentials, itemIndex } = options;
		const apiVersion = fns.getNodeParameter('version', itemIndex) as string;
		const recordType = NetSuiteCustom.getRecordType(options);
		const internalId = fns.getNodeParameter('internalId', itemIndex) as string;
		const requestData = {
			method: 'DELETE',
			requestType: NetSuiteRequestType.Record,
			path: `services/rest/record/${apiVersion}/${recordType}/${internalId}`,
		};
		const response = await makeRequest(getConfig(credentials), requestData);
		return handleNetsuiteResponse(fns, response);
	}

	static async insertRecord(options: INetSuiteOperationOptions): Promise<INodeExecutionData> {
		const { fns, credentials, itemIndex, item } = options;
		const apiVersion = fns.getNodeParameter('version', itemIndex) as string;
		const recordType = NetSuiteCustom.getRecordType(options);
		const query = item ? item.json : undefined;
		const requestData: INetSuiteRequestOptions = {
			method: 'POST',
			requestType: NetSuiteRequestType.Record,
			path: `services/rest/record/${apiVersion}/${recordType}`,
		};
		if (query) requestData.query = query;
		const response = await makeRequest(getConfig(credentials), requestData);
		return handleNetsuiteResponse(fns, response);
	}

	static async updateRecord(options: INetSuiteOperationOptions): Promise<INodeExecutionData> {
		const { fns, credentials, itemIndex, item } = options;
		const apiVersion = fns.getNodeParameter('version', itemIndex) as string;
		const recordType = NetSuiteCustom.getRecordType(options);
		const internalId = fns.getNodeParameter('internalId', itemIndex) as string;
		const query = item ? item.json : undefined;
		const requestData: INetSuiteRequestOptions = {
			method: 'PATCH',
			requestType: NetSuiteRequestType.Record,
			path: `services/rest/record/${apiVersion}/${recordType}/${internalId}`,
		};
		if (query) requestData.query = query;
		const response = await makeRequest(getConfig(credentials), requestData);
		return handleNetsuiteResponse(fns, response);
	}

	static async rawRequest(options: INetSuiteOperationOptions): Promise<INodeExecutionData> {
		const { fns, credentials, itemIndex, item } = options;
		const nodeContext = fns.getContext('node');
		let path = fns.getNodeParameter('path', itemIndex) as string;
		const method = fns.getNodeParameter('method', itemIndex) as string;
		const body = fns.getNodeParameter('body', itemIndex) as string;
		const requestType = fns.getNodeParameter('requestType', itemIndex) as NetSuiteRequestType;
		const query = body || (item ? item.json : undefined);
		const nodeOptions = fns.getNodeParameter('options', 0) as IDataObject;

		// Get custom headers
		const customHeadersData = fns.getNodeParameter('customHeaders', itemIndex, {}) as IDataObject;
		const customHeaders: Record<string, string> = {};

		if (customHeadersData.header && Array.isArray(customHeadersData.header)) {
			for (const headerItem of customHeadersData.header) {
				const headerObj = headerItem as { name: string; value: string };
				if (headerObj.name && headerObj.value) {
					customHeaders[headerObj.name] = headerObj.value;
				}
			}
		}

		if (path && (path.startsWith('https://') || path.startsWith('http://'))) {
			const url = new URL(path);
			path = `${url.pathname.replace(/^\//, '')}${url.search || ''}`;
		}

		// Build full URL
		const fullUrl = `https://${credentials.hostname}/${path}`;

		// Get OAuth headers
		const oauthHeaders = getOAuthHeaders(credentials, { url: fullUrl, method });

		// Merge headers: OAuth + default + custom (custom can override defaults)
		const headers: Record<string, string> = {
			...oauthHeaders,
			'Content-Type': 'application/json; charset=utf-8',
			'prefer': 'transient',
			...customHeaders,  // Custom headers override defaults
		};

		debug('rawRequest URL:', fullUrl);
		debug('rawRequest headers:', headers);

		// Build request body
		let requestBody: any = undefined;
		if (query && !['GET', 'HEAD', 'OPTIONS'].includes(method)) {
			if (requestType === 'suiteql') {
				requestBody = { q: query };
			} else {
				requestBody = typeof query === 'string' ? JSON.parse(query) : query;
			}
		}

		// Make the request using n8n's built-in httpRequest helper
		const response = await fns.helpers.httpRequest({
			method: method as IHttpRequestMethods,
			url: fullUrl,
			headers,
			body: requestBody,
			returnFullResponse: true,
			ignoreHttpStatusErrors: true,
			json: true,
		});

		const respBody = response.body as any;

		if (respBody) {
			nodeContext.hasMore = respBody.hasMore;
			nodeContext.count = respBody.count;
			nodeContext.offset = respBody.offset;
			nodeContext.totalResults = respBody.totalResults;
		}

		if (nodeOptions.fullResponse) {
			return {
				json: {
					statusCode: response.statusCode,
					headers: response.headers,
					body: respBody,
				},
			};
		} else {
			return { json: respBody as JsonObject };
		}
	}

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const credentials: INetSuiteCredentials = (await this.getCredentials('netsuiteCustom')) as INetSuiteCredentials;
		const operation = this.getNodeParameter('operation', 0) as string;
		const items: INodeExecutionData[] = this.getInputData();
		const returnData: INodeExecutionData[] = [];
		const promises = [];
		const options = this.getNodeParameter('options', 0) as IDataObject;
		const concurrency = options.concurrency as number || 1;
		const limit = pLimit(concurrency);

		for (let itemIndex = 0; itemIndex < items.length; itemIndex++) {
			const item: INodeExecutionData = items[itemIndex];
			let data: INodeExecutionData | INodeExecutionData[];

			promises.push(limit(async () =>{
				debug(`Processing ${operation} for ${itemIndex+1} of ${items.length}`);
				if (operation === 'getRecord') {
					data = await NetSuiteCustom.getRecord({ item, fns: this, credentials, itemIndex});
				} else if (operation === 'listRecords') {
					data = await NetSuiteCustom.listRecords({ item, fns: this, credentials, itemIndex});
				} else if (operation === 'removeRecord') {
					data = await NetSuiteCustom.removeRecord({ item, fns: this, credentials, itemIndex});
				} else if (operation === 'insertRecord') {
					data = await NetSuiteCustom.insertRecord({ item, fns: this, credentials, itemIndex});
				} else if (operation === 'updateRecord') {
					data = await NetSuiteCustom.updateRecord({ item, fns: this, credentials, itemIndex});
				} else if (operation === 'rawRequest') {
					data = await NetSuiteCustom.rawRequest({ item, fns: this, credentials, itemIndex});
				} else if (operation === 'runSuiteQL') {
					data = await NetSuiteCustom.runSuiteQL({ item, fns: this, credentials, itemIndex});
				} else {
					const error = `The operation "${operation}" is not supported!`;
					if (this.continueOnFail() !== true) {
						throw new Error(error);
					} else {
						data = { json: { error } };
					}
				}
				return data;
			}));
		}

		const results = await Promise.all(promises);
		for await (const result of results) {
			if (result) {
				if (Array.isArray(result)) {
					returnData.push(...result);
				} else {
					returnData.push(result);
				}
			}
		}

		return this.prepareOutputData(returnData);
	}
}
