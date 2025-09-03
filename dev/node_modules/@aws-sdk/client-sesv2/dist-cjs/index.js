"use strict";
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var index_exports = {};
__export(index_exports, {
  AccountDetailsFilterSensitiveLog: () => AccountDetailsFilterSensitiveLog,
  AccountSuspendedException: () => AccountSuspendedException,
  AlreadyExistsException: () => AlreadyExistsException,
  AttachmentContentDisposition: () => AttachmentContentDisposition,
  AttachmentContentTransferEncoding: () => AttachmentContentTransferEncoding,
  BadRequestException: () => BadRequestException,
  BatchGetMetricDataCommand: () => BatchGetMetricDataCommand,
  BehaviorOnMxFailure: () => BehaviorOnMxFailure,
  BounceType: () => BounceType,
  BulkEmailStatus: () => BulkEmailStatus,
  CancelExportJobCommand: () => CancelExportJobCommand,
  ConcurrentModificationException: () => ConcurrentModificationException,
  ConflictException: () => ConflictException,
  ContactLanguage: () => ContactLanguage,
  ContactListImportAction: () => ContactListImportAction,
  CreateConfigurationSetCommand: () => CreateConfigurationSetCommand,
  CreateConfigurationSetEventDestinationCommand: () => CreateConfigurationSetEventDestinationCommand,
  CreateContactCommand: () => CreateContactCommand,
  CreateContactListCommand: () => CreateContactListCommand,
  CreateCustomVerificationEmailTemplateCommand: () => CreateCustomVerificationEmailTemplateCommand,
  CreateDedicatedIpPoolCommand: () => CreateDedicatedIpPoolCommand,
  CreateDeliverabilityTestReportCommand: () => CreateDeliverabilityTestReportCommand,
  CreateEmailIdentityCommand: () => CreateEmailIdentityCommand,
  CreateEmailIdentityPolicyCommand: () => CreateEmailIdentityPolicyCommand,
  CreateEmailIdentityRequestFilterSensitiveLog: () => CreateEmailIdentityRequestFilterSensitiveLog,
  CreateEmailTemplateCommand: () => CreateEmailTemplateCommand,
  CreateExportJobCommand: () => CreateExportJobCommand,
  CreateExportJobRequestFilterSensitiveLog: () => CreateExportJobRequestFilterSensitiveLog,
  CreateImportJobCommand: () => CreateImportJobCommand,
  CreateMultiRegionEndpointCommand: () => CreateMultiRegionEndpointCommand,
  CreateTenantCommand: () => CreateTenantCommand,
  CreateTenantResourceAssociationCommand: () => CreateTenantResourceAssociationCommand,
  DataFormat: () => DataFormat,
  DeleteConfigurationSetCommand: () => DeleteConfigurationSetCommand,
  DeleteConfigurationSetEventDestinationCommand: () => DeleteConfigurationSetEventDestinationCommand,
  DeleteContactCommand: () => DeleteContactCommand,
  DeleteContactListCommand: () => DeleteContactListCommand,
  DeleteCustomVerificationEmailTemplateCommand: () => DeleteCustomVerificationEmailTemplateCommand,
  DeleteDedicatedIpPoolCommand: () => DeleteDedicatedIpPoolCommand,
  DeleteEmailIdentityCommand: () => DeleteEmailIdentityCommand,
  DeleteEmailIdentityPolicyCommand: () => DeleteEmailIdentityPolicyCommand,
  DeleteEmailTemplateCommand: () => DeleteEmailTemplateCommand,
  DeleteMultiRegionEndpointCommand: () => DeleteMultiRegionEndpointCommand,
  DeleteSuppressedDestinationCommand: () => DeleteSuppressedDestinationCommand,
  DeleteTenantCommand: () => DeleteTenantCommand,
  DeleteTenantResourceAssociationCommand: () => DeleteTenantResourceAssociationCommand,
  DeliverabilityDashboardAccountStatus: () => DeliverabilityDashboardAccountStatus,
  DeliverabilityTestStatus: () => DeliverabilityTestStatus,
  DeliveryEventType: () => DeliveryEventType,
  DimensionValueSource: () => DimensionValueSource,
  DkimSigningAttributesFilterSensitiveLog: () => DkimSigningAttributesFilterSensitiveLog,
  DkimSigningAttributesOrigin: () => DkimSigningAttributesOrigin,
  DkimSigningKeyLength: () => DkimSigningKeyLength,
  DkimStatus: () => DkimStatus,
  EmailInsightsFilterSensitiveLog: () => EmailInsightsFilterSensitiveLog,
  EngagementEventType: () => EngagementEventType,
  EventType: () => EventType,
  ExportDataSourceFilterSensitiveLog: () => ExportDataSourceFilterSensitiveLog,
  ExportSourceType: () => ExportSourceType,
  FeatureStatus: () => FeatureStatus,
  GetAccountCommand: () => GetAccountCommand,
  GetAccountResponseFilterSensitiveLog: () => GetAccountResponseFilterSensitiveLog,
  GetBlacklistReportsCommand: () => GetBlacklistReportsCommand,
  GetConfigurationSetCommand: () => GetConfigurationSetCommand,
  GetConfigurationSetEventDestinationsCommand: () => GetConfigurationSetEventDestinationsCommand,
  GetContactCommand: () => GetContactCommand,
  GetContactListCommand: () => GetContactListCommand,
  GetCustomVerificationEmailTemplateCommand: () => GetCustomVerificationEmailTemplateCommand,
  GetDedicatedIpCommand: () => GetDedicatedIpCommand,
  GetDedicatedIpPoolCommand: () => GetDedicatedIpPoolCommand,
  GetDedicatedIpsCommand: () => GetDedicatedIpsCommand,
  GetDeliverabilityDashboardOptionsCommand: () => GetDeliverabilityDashboardOptionsCommand,
  GetDeliverabilityTestReportCommand: () => GetDeliverabilityTestReportCommand,
  GetDomainDeliverabilityCampaignCommand: () => GetDomainDeliverabilityCampaignCommand,
  GetDomainStatisticsReportCommand: () => GetDomainStatisticsReportCommand,
  GetEmailIdentityCommand: () => GetEmailIdentityCommand,
  GetEmailIdentityPoliciesCommand: () => GetEmailIdentityPoliciesCommand,
  GetEmailTemplateCommand: () => GetEmailTemplateCommand,
  GetExportJobCommand: () => GetExportJobCommand,
  GetExportJobResponseFilterSensitiveLog: () => GetExportJobResponseFilterSensitiveLog,
  GetImportJobCommand: () => GetImportJobCommand,
  GetMessageInsightsCommand: () => GetMessageInsightsCommand,
  GetMessageInsightsResponseFilterSensitiveLog: () => GetMessageInsightsResponseFilterSensitiveLog,
  GetMultiRegionEndpointCommand: () => GetMultiRegionEndpointCommand,
  GetReputationEntityCommand: () => GetReputationEntityCommand,
  GetSuppressedDestinationCommand: () => GetSuppressedDestinationCommand,
  GetTenantCommand: () => GetTenantCommand,
  HttpsPolicy: () => HttpsPolicy,
  IdentityType: () => IdentityType,
  ImportDestinationType: () => ImportDestinationType,
  InternalServiceErrorException: () => InternalServiceErrorException,
  InvalidNextTokenException: () => InvalidNextTokenException,
  JobStatus: () => JobStatus,
  LimitExceededException: () => LimitExceededException,
  ListConfigurationSetsCommand: () => ListConfigurationSetsCommand,
  ListContactListsCommand: () => ListContactListsCommand,
  ListContactsCommand: () => ListContactsCommand,
  ListCustomVerificationEmailTemplatesCommand: () => ListCustomVerificationEmailTemplatesCommand,
  ListDedicatedIpPoolsCommand: () => ListDedicatedIpPoolsCommand,
  ListDeliverabilityTestReportsCommand: () => ListDeliverabilityTestReportsCommand,
  ListDomainDeliverabilityCampaignsCommand: () => ListDomainDeliverabilityCampaignsCommand,
  ListEmailIdentitiesCommand: () => ListEmailIdentitiesCommand,
  ListEmailTemplatesCommand: () => ListEmailTemplatesCommand,
  ListExportJobsCommand: () => ListExportJobsCommand,
  ListImportJobsCommand: () => ListImportJobsCommand,
  ListMultiRegionEndpointsCommand: () => ListMultiRegionEndpointsCommand,
  ListRecommendationsCommand: () => ListRecommendationsCommand,
  ListRecommendationsFilterKey: () => ListRecommendationsFilterKey,
  ListReputationEntitiesCommand: () => ListReputationEntitiesCommand,
  ListResourceTenantsCommand: () => ListResourceTenantsCommand,
  ListSuppressedDestinationsCommand: () => ListSuppressedDestinationsCommand,
  ListTagsForResourceCommand: () => ListTagsForResourceCommand,
  ListTenantResourcesCommand: () => ListTenantResourcesCommand,
  ListTenantResourcesFilterKey: () => ListTenantResourcesFilterKey,
  ListTenantsCommand: () => ListTenantsCommand,
  MailFromDomainNotVerifiedException: () => MailFromDomainNotVerifiedException,
  MailFromDomainStatus: () => MailFromDomainStatus,
  MailType: () => MailType,
  MessageInsightsDataSourceFilterSensitiveLog: () => MessageInsightsDataSourceFilterSensitiveLog,
  MessageInsightsFiltersFilterSensitiveLog: () => MessageInsightsFiltersFilterSensitiveLog,
  MessageRejected: () => MessageRejected,
  Metric: () => Metric,
  MetricAggregation: () => MetricAggregation,
  MetricDimensionName: () => MetricDimensionName,
  MetricNamespace: () => MetricNamespace,
  NotFoundException: () => NotFoundException,
  PutAccountDedicatedIpWarmupAttributesCommand: () => PutAccountDedicatedIpWarmupAttributesCommand,
  PutAccountDetailsCommand: () => PutAccountDetailsCommand,
  PutAccountDetailsRequestFilterSensitiveLog: () => PutAccountDetailsRequestFilterSensitiveLog,
  PutAccountSendingAttributesCommand: () => PutAccountSendingAttributesCommand,
  PutAccountSuppressionAttributesCommand: () => PutAccountSuppressionAttributesCommand,
  PutAccountVdmAttributesCommand: () => PutAccountVdmAttributesCommand,
  PutConfigurationSetArchivingOptionsCommand: () => PutConfigurationSetArchivingOptionsCommand,
  PutConfigurationSetDeliveryOptionsCommand: () => PutConfigurationSetDeliveryOptionsCommand,
  PutConfigurationSetReputationOptionsCommand: () => PutConfigurationSetReputationOptionsCommand,
  PutConfigurationSetSendingOptionsCommand: () => PutConfigurationSetSendingOptionsCommand,
  PutConfigurationSetSuppressionOptionsCommand: () => PutConfigurationSetSuppressionOptionsCommand,
  PutConfigurationSetTrackingOptionsCommand: () => PutConfigurationSetTrackingOptionsCommand,
  PutConfigurationSetVdmOptionsCommand: () => PutConfigurationSetVdmOptionsCommand,
  PutDedicatedIpInPoolCommand: () => PutDedicatedIpInPoolCommand,
  PutDedicatedIpPoolScalingAttributesCommand: () => PutDedicatedIpPoolScalingAttributesCommand,
  PutDedicatedIpWarmupAttributesCommand: () => PutDedicatedIpWarmupAttributesCommand,
  PutDeliverabilityDashboardOptionCommand: () => PutDeliverabilityDashboardOptionCommand,
  PutEmailIdentityConfigurationSetAttributesCommand: () => PutEmailIdentityConfigurationSetAttributesCommand,
  PutEmailIdentityDkimAttributesCommand: () => PutEmailIdentityDkimAttributesCommand,
  PutEmailIdentityDkimSigningAttributesCommand: () => PutEmailIdentityDkimSigningAttributesCommand,
  PutEmailIdentityDkimSigningAttributesRequestFilterSensitiveLog: () => PutEmailIdentityDkimSigningAttributesRequestFilterSensitiveLog,
  PutEmailIdentityFeedbackAttributesCommand: () => PutEmailIdentityFeedbackAttributesCommand,
  PutEmailIdentityMailFromAttributesCommand: () => PutEmailIdentityMailFromAttributesCommand,
  PutSuppressedDestinationCommand: () => PutSuppressedDestinationCommand,
  QueryErrorCode: () => QueryErrorCode,
  RecommendationImpact: () => RecommendationImpact,
  RecommendationStatus: () => RecommendationStatus,
  RecommendationType: () => RecommendationType,
  ReputationEntityFilterKey: () => ReputationEntityFilterKey,
  ReputationEntityType: () => ReputationEntityType,
  ResourceType: () => ResourceType,
  ReviewStatus: () => ReviewStatus,
  SESv2: () => SESv2,
  SESv2Client: () => SESv2Client,
  SESv2ServiceException: () => SESv2ServiceException,
  ScalingMode: () => ScalingMode,
  SendBulkEmailCommand: () => SendBulkEmailCommand,
  SendCustomVerificationEmailCommand: () => SendCustomVerificationEmailCommand,
  SendEmailCommand: () => SendEmailCommand,
  SendingPausedException: () => SendingPausedException,
  SendingStatus: () => SendingStatus,
  Status: () => Status,
  SubscriptionStatus: () => SubscriptionStatus,
  SuppressionListImportAction: () => SuppressionListImportAction,
  SuppressionListReason: () => SuppressionListReason,
  TagResourceCommand: () => TagResourceCommand,
  TestRenderEmailTemplateCommand: () => TestRenderEmailTemplateCommand,
  TlsPolicy: () => TlsPolicy,
  TooManyRequestsException: () => TooManyRequestsException,
  UntagResourceCommand: () => UntagResourceCommand,
  UpdateConfigurationSetEventDestinationCommand: () => UpdateConfigurationSetEventDestinationCommand,
  UpdateContactCommand: () => UpdateContactCommand,
  UpdateContactListCommand: () => UpdateContactListCommand,
  UpdateCustomVerificationEmailTemplateCommand: () => UpdateCustomVerificationEmailTemplateCommand,
  UpdateEmailIdentityPolicyCommand: () => UpdateEmailIdentityPolicyCommand,
  UpdateEmailTemplateCommand: () => UpdateEmailTemplateCommand,
  UpdateReputationEntityCustomerManagedStatusCommand: () => UpdateReputationEntityCustomerManagedStatusCommand,
  UpdateReputationEntityPolicyCommand: () => UpdateReputationEntityPolicyCommand,
  VerificationError: () => VerificationError,
  VerificationStatus: () => VerificationStatus,
  WarmupStatus: () => WarmupStatus,
  __Client: () => import_smithy_client.Client,
  paginateGetDedicatedIps: () => paginateGetDedicatedIps,
  paginateListConfigurationSets: () => paginateListConfigurationSets,
  paginateListContactLists: () => paginateListContactLists,
  paginateListContacts: () => paginateListContacts,
  paginateListCustomVerificationEmailTemplates: () => paginateListCustomVerificationEmailTemplates,
  paginateListDedicatedIpPools: () => paginateListDedicatedIpPools,
  paginateListDeliverabilityTestReports: () => paginateListDeliverabilityTestReports,
  paginateListDomainDeliverabilityCampaigns: () => paginateListDomainDeliverabilityCampaigns,
  paginateListEmailIdentities: () => paginateListEmailIdentities,
  paginateListEmailTemplates: () => paginateListEmailTemplates,
  paginateListExportJobs: () => paginateListExportJobs,
  paginateListImportJobs: () => paginateListImportJobs,
  paginateListMultiRegionEndpoints: () => paginateListMultiRegionEndpoints,
  paginateListRecommendations: () => paginateListRecommendations,
  paginateListReputationEntities: () => paginateListReputationEntities,
  paginateListResourceTenants: () => paginateListResourceTenants,
  paginateListSuppressedDestinations: () => paginateListSuppressedDestinations,
  paginateListTenantResources: () => paginateListTenantResources,
  paginateListTenants: () => paginateListTenants
});
module.exports = __toCommonJS(index_exports);

// src/SESv2Client.ts
var import_middleware_host_header = require("@aws-sdk/middleware-host-header");
var import_middleware_logger = require("@aws-sdk/middleware-logger");
var import_middleware_recursion_detection = require("@aws-sdk/middleware-recursion-detection");
var import_middleware_user_agent = require("@aws-sdk/middleware-user-agent");
var import_config_resolver = require("@smithy/config-resolver");
var import_core = require("@smithy/core");
var import_middleware_content_length = require("@smithy/middleware-content-length");
var import_middleware_endpoint = require("@smithy/middleware-endpoint");
var import_middleware_retry = require("@smithy/middleware-retry");

var import_httpAuthSchemeProvider = require("./auth/httpAuthSchemeProvider");

// src/endpoint/EndpointParameters.ts
var resolveClientEndpointParameters = /* @__PURE__ */ __name((options) => {
  return Object.assign(options, {
    useDualstackEndpoint: options.useDualstackEndpoint ?? false,
    useFipsEndpoint: options.useFipsEndpoint ?? false,
    defaultSigningName: "ses"
  });
}, "resolveClientEndpointParameters");
var commonParams = {
  UseFIPS: { type: "builtInParams", name: "useFipsEndpoint" },
  Endpoint: { type: "builtInParams", name: "endpoint" },
  Region: { type: "builtInParams", name: "region" },
  UseDualStack: { type: "builtInParams", name: "useDualstackEndpoint" }
};

// src/SESv2Client.ts
var import_runtimeConfig = require("././runtimeConfig");

// src/runtimeExtensions.ts
var import_region_config_resolver = require("@aws-sdk/region-config-resolver");
var import_protocol_http = require("@smithy/protocol-http");
var import_smithy_client = require("@smithy/smithy-client");

// src/auth/httpAuthExtensionConfiguration.ts
var getHttpAuthExtensionConfiguration = /* @__PURE__ */ __name((runtimeConfig) => {
  const _httpAuthSchemes = runtimeConfig.httpAuthSchemes;
  let _httpAuthSchemeProvider = runtimeConfig.httpAuthSchemeProvider;
  let _credentials = runtimeConfig.credentials;
  return {
    setHttpAuthScheme(httpAuthScheme) {
      const index = _httpAuthSchemes.findIndex((scheme) => scheme.schemeId === httpAuthScheme.schemeId);
      if (index === -1) {
        _httpAuthSchemes.push(httpAuthScheme);
      } else {
        _httpAuthSchemes.splice(index, 1, httpAuthScheme);
      }
    },
    httpAuthSchemes() {
      return _httpAuthSchemes;
    },
    setHttpAuthSchemeProvider(httpAuthSchemeProvider) {
      _httpAuthSchemeProvider = httpAuthSchemeProvider;
    },
    httpAuthSchemeProvider() {
      return _httpAuthSchemeProvider;
    },
    setCredentials(credentials) {
      _credentials = credentials;
    },
    credentials() {
      return _credentials;
    }
  };
}, "getHttpAuthExtensionConfiguration");
var resolveHttpAuthRuntimeConfig = /* @__PURE__ */ __name((config) => {
  return {
    httpAuthSchemes: config.httpAuthSchemes(),
    httpAuthSchemeProvider: config.httpAuthSchemeProvider(),
    credentials: config.credentials()
  };
}, "resolveHttpAuthRuntimeConfig");

// src/runtimeExtensions.ts
var resolveRuntimeExtensions = /* @__PURE__ */ __name((runtimeConfig, extensions) => {
  const extensionConfiguration = Object.assign(
    (0, import_region_config_resolver.getAwsRegionExtensionConfiguration)(runtimeConfig),
    (0, import_smithy_client.getDefaultExtensionConfiguration)(runtimeConfig),
    (0, import_protocol_http.getHttpHandlerExtensionConfiguration)(runtimeConfig),
    getHttpAuthExtensionConfiguration(runtimeConfig)
  );
  extensions.forEach((extension) => extension.configure(extensionConfiguration));
  return Object.assign(
    runtimeConfig,
    (0, import_region_config_resolver.resolveAwsRegionExtensionConfiguration)(extensionConfiguration),
    (0, import_smithy_client.resolveDefaultRuntimeConfig)(extensionConfiguration),
    (0, import_protocol_http.resolveHttpHandlerRuntimeConfig)(extensionConfiguration),
    resolveHttpAuthRuntimeConfig(extensionConfiguration)
  );
}, "resolveRuntimeExtensions");

// src/SESv2Client.ts
var SESv2Client = class extends import_smithy_client.Client {
  static {
    __name(this, "SESv2Client");
  }
  /**
   * The resolved configuration of SESv2Client class. This is resolved and normalized from the {@link SESv2ClientConfig | constructor configuration interface}.
   */
  config;
  constructor(...[configuration]) {
    const _config_0 = (0, import_runtimeConfig.getRuntimeConfig)(configuration || {});
    super(_config_0);
    this.initConfig = _config_0;
    const _config_1 = resolveClientEndpointParameters(_config_0);
    const _config_2 = (0, import_middleware_user_agent.resolveUserAgentConfig)(_config_1);
    const _config_3 = (0, import_middleware_retry.resolveRetryConfig)(_config_2);
    const _config_4 = (0, import_config_resolver.resolveRegionConfig)(_config_3);
    const _config_5 = (0, import_middleware_host_header.resolveHostHeaderConfig)(_config_4);
    const _config_6 = (0, import_middleware_endpoint.resolveEndpointConfig)(_config_5);
    const _config_7 = (0, import_httpAuthSchemeProvider.resolveHttpAuthSchemeConfig)(_config_6);
    const _config_8 = resolveRuntimeExtensions(_config_7, configuration?.extensions || []);
    this.config = _config_8;
    this.middlewareStack.use((0, import_middleware_user_agent.getUserAgentPlugin)(this.config));
    this.middlewareStack.use((0, import_middleware_retry.getRetryPlugin)(this.config));
    this.middlewareStack.use((0, import_middleware_content_length.getContentLengthPlugin)(this.config));
    this.middlewareStack.use((0, import_middleware_host_header.getHostHeaderPlugin)(this.config));
    this.middlewareStack.use((0, import_middleware_logger.getLoggerPlugin)(this.config));
    this.middlewareStack.use((0, import_middleware_recursion_detection.getRecursionDetectionPlugin)(this.config));
    this.middlewareStack.use(
      (0, import_core.getHttpAuthSchemeEndpointRuleSetPlugin)(this.config, {
        httpAuthSchemeParametersProvider: import_httpAuthSchemeProvider.defaultSESv2HttpAuthSchemeParametersProvider,
        identityProviderConfigProvider: /* @__PURE__ */ __name(async (config) => new import_core.DefaultIdentityProviderConfig({
          "aws.auth#sigv4": config.credentials,
          "aws.auth#sigv4a": config.credentials
        }), "identityProviderConfigProvider")
      })
    );
    this.middlewareStack.use((0, import_core.getHttpSigningPlugin)(this.config));
  }
  /**
   * Destroy underlying resources, like sockets. It's usually not necessary to do this.
   * However in Node.js, it's best to explicitly shut down the client's agent when it is no longer needed.
   * Otherwise, sockets might stay open for quite a long time before the server terminates them.
   */
  destroy() {
    super.destroy();
  }
};

// src/SESv2.ts


// src/commands/BatchGetMetricDataCommand.ts

var import_middleware_serde = require("@smithy/middleware-serde");


// src/protocols/Aws_restJson1.ts
var import_core2 = require("@aws-sdk/core");



// src/models/models_0.ts


// src/models/SESv2ServiceException.ts

var SESv2ServiceException = class _SESv2ServiceException extends import_smithy_client.ServiceException {
  static {
    __name(this, "SESv2ServiceException");
  }
  /**
   * @internal
   */
  constructor(options) {
    super(options);
    Object.setPrototypeOf(this, _SESv2ServiceException.prototype);
  }
};

// src/models/models_0.ts
var ContactLanguage = {
  EN: "EN",
  JA: "JA"
};
var MailType = {
  MARKETING: "MARKETING",
  TRANSACTIONAL: "TRANSACTIONAL"
};
var ReviewStatus = {
  DENIED: "DENIED",
  FAILED: "FAILED",
  GRANTED: "GRANTED",
  PENDING: "PENDING"
};
var AccountSuspendedException = class _AccountSuspendedException extends SESv2ServiceException {
  static {
    __name(this, "AccountSuspendedException");
  }
  name = "AccountSuspendedException";
  $fault = "client";
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "AccountSuspendedException",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _AccountSuspendedException.prototype);
  }
};
var AlreadyExistsException = class _AlreadyExistsException extends SESv2ServiceException {
  static {
    __name(this, "AlreadyExistsException");
  }
  name = "AlreadyExistsException";
  $fault = "client";
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "AlreadyExistsException",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _AlreadyExistsException.prototype);
  }
};
var AttachmentContentDisposition = {
  ATTACHMENT: "ATTACHMENT",
  INLINE: "INLINE"
};
var AttachmentContentTransferEncoding = {
  BASE64: "BASE64",
  QUOTED_PRINTABLE: "QUOTED_PRINTABLE",
  SEVEN_BIT: "SEVEN_BIT"
};
var BadRequestException = class _BadRequestException extends SESv2ServiceException {
  static {
    __name(this, "BadRequestException");
  }
  name = "BadRequestException";
  $fault = "client";
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "BadRequestException",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _BadRequestException.prototype);
  }
};
var MetricDimensionName = {
  CONFIGURATION_SET: "CONFIGURATION_SET",
  EMAIL_IDENTITY: "EMAIL_IDENTITY",
  ISP: "ISP"
};
var Metric = {
  CLICK: "CLICK",
  COMPLAINT: "COMPLAINT",
  DELIVERY: "DELIVERY",
  DELIVERY_CLICK: "DELIVERY_CLICK",
  DELIVERY_COMPLAINT: "DELIVERY_COMPLAINT",
  DELIVERY_OPEN: "DELIVERY_OPEN",
  OPEN: "OPEN",
  PERMANENT_BOUNCE: "PERMANENT_BOUNCE",
  SEND: "SEND",
  TRANSIENT_BOUNCE: "TRANSIENT_BOUNCE"
};
var MetricNamespace = {
  VDM: "VDM"
};
var QueryErrorCode = {
  ACCESS_DENIED: "ACCESS_DENIED",
  INTERNAL_FAILURE: "INTERNAL_FAILURE"
};
var InternalServiceErrorException = class _InternalServiceErrorException extends SESv2ServiceException {
  static {
    __name(this, "InternalServiceErrorException");
  }
  name = "InternalServiceErrorException";
  $fault = "server";
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "InternalServiceErrorException",
      $fault: "server",
      ...opts
    });
    Object.setPrototypeOf(this, _InternalServiceErrorException.prototype);
  }
};
var NotFoundException = class _NotFoundException extends SESv2ServiceException {
  static {
    __name(this, "NotFoundException");
  }
  name = "NotFoundException";
  $fault = "client";
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "NotFoundException",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _NotFoundException.prototype);
  }
};
var TooManyRequestsException = class _TooManyRequestsException extends SESv2ServiceException {
  static {
    __name(this, "TooManyRequestsException");
  }
  name = "TooManyRequestsException";
  $fault = "client";
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "TooManyRequestsException",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _TooManyRequestsException.prototype);
  }
};
var BehaviorOnMxFailure = {
  REJECT_MESSAGE: "REJECT_MESSAGE",
  USE_DEFAULT_VALUE: "USE_DEFAULT_VALUE"
};
var BounceType = {
  PERMANENT: "PERMANENT",
  TRANSIENT: "TRANSIENT",
  UNDETERMINED: "UNDETERMINED"
};
var BulkEmailStatus = {
  ACCOUNT_DAILY_QUOTA_EXCEEDED: "ACCOUNT_DAILY_QUOTA_EXCEEDED",
  ACCOUNT_SENDING_PAUSED: "ACCOUNT_SENDING_PAUSED",
  ACCOUNT_SUSPENDED: "ACCOUNT_SUSPENDED",
  ACCOUNT_THROTTLED: "ACCOUNT_THROTTLED",
  CONFIGURATION_SET_NOT_FOUND: "CONFIGURATION_SET_NOT_FOUND",
  CONFIGURATION_SET_SENDING_PAUSED: "CONFIGURATION_SET_SENDING_PAUSED",
  FAILED: "FAILED",
  INVALID_PARAMETER: "INVALID_PARAMETER",
  INVALID_SENDING_POOL_NAME: "INVALID_SENDING_POOL_NAME",
  MAIL_FROM_DOMAIN_NOT_VERIFIED: "MAIL_FROM_DOMAIN_NOT_VERIFIED",
  MESSAGE_REJECTED: "MESSAGE_REJECTED",
  SUCCESS: "SUCCESS",
  TEMPLATE_NOT_FOUND: "TEMPLATE_NOT_FOUND",
  TRANSIENT_FAILURE: "TRANSIENT_FAILURE"
};
var DimensionValueSource = {
  EMAIL_HEADER: "EMAIL_HEADER",
  LINK_TAG: "LINK_TAG",
  MESSAGE_TAG: "MESSAGE_TAG"
};
var ConcurrentModificationException = class _ConcurrentModificationException extends SESv2ServiceException {
  static {
    __name(this, "ConcurrentModificationException");
  }
  name = "ConcurrentModificationException";
  $fault = "server";
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "ConcurrentModificationException",
      $fault: "server",
      ...opts
    });
    Object.setPrototypeOf(this, _ConcurrentModificationException.prototype);
  }
};
var ConflictException = class _ConflictException extends SESv2ServiceException {
  static {
    __name(this, "ConflictException");
  }
  name = "ConflictException";
  $fault = "client";
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "ConflictException",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _ConflictException.prototype);
  }
};
var SubscriptionStatus = {
  OPT_IN: "OPT_IN",
  OPT_OUT: "OPT_OUT"
};
var ContactListImportAction = {
  DELETE: "DELETE",
  PUT: "PUT"
};
var TlsPolicy = {
  OPTIONAL: "OPTIONAL",
  REQUIRE: "REQUIRE"
};
var SuppressionListReason = {
  BOUNCE: "BOUNCE",
  COMPLAINT: "COMPLAINT"
};
var HttpsPolicy = {
  OPTIONAL: "OPTIONAL",
  REQUIRE: "REQUIRE",
  REQUIRE_OPEN_ONLY: "REQUIRE_OPEN_ONLY"
};
var FeatureStatus = {
  DISABLED: "DISABLED",
  ENABLED: "ENABLED"
};
var LimitExceededException = class _LimitExceededException extends SESv2ServiceException {
  static {
    __name(this, "LimitExceededException");
  }
  name = "LimitExceededException";
  $fault = "client";
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "LimitExceededException",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _LimitExceededException.prototype);
  }
};
var EventType = {
  BOUNCE: "BOUNCE",
  CLICK: "CLICK",
  COMPLAINT: "COMPLAINT",
  DELIVERY: "DELIVERY",
  DELIVERY_DELAY: "DELIVERY_DELAY",
  OPEN: "OPEN",
  REJECT: "REJECT",
  RENDERING_FAILURE: "RENDERING_FAILURE",
  SEND: "SEND",
  SUBSCRIPTION: "SUBSCRIPTION"
};
var ScalingMode = {
  MANAGED: "MANAGED",
  STANDARD: "STANDARD"
};
var DeliverabilityTestStatus = {
  COMPLETED: "COMPLETED",
  IN_PROGRESS: "IN_PROGRESS"
};
var MailFromDomainNotVerifiedException = class _MailFromDomainNotVerifiedException extends SESv2ServiceException {
  static {
    __name(this, "MailFromDomainNotVerifiedException");
  }
  name = "MailFromDomainNotVerifiedException";
  $fault = "client";
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "MailFromDomainNotVerifiedException",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _MailFromDomainNotVerifiedException.prototype);
  }
};
var MessageRejected = class _MessageRejected extends SESv2ServiceException {
  static {
    __name(this, "MessageRejected");
  }
  name = "MessageRejected";
  $fault = "client";
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "MessageRejected",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _MessageRejected.prototype);
  }
};
var SendingPausedException = class _SendingPausedException extends SESv2ServiceException {
  static {
    __name(this, "SendingPausedException");
  }
  name = "SendingPausedException";
  $fault = "client";
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "SendingPausedException",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _SendingPausedException.prototype);
  }
};
var DkimSigningAttributesOrigin = {
  AWS_SES: "AWS_SES",
  AWS_SES_AF_SOUTH_1: "AWS_SES_AF_SOUTH_1",
  AWS_SES_AP_NORTHEAST_1: "AWS_SES_AP_NORTHEAST_1",
  AWS_SES_AP_NORTHEAST_2: "AWS_SES_AP_NORTHEAST_2",
  AWS_SES_AP_NORTHEAST_3: "AWS_SES_AP_NORTHEAST_3",
  AWS_SES_AP_SOUTHEAST_1: "AWS_SES_AP_SOUTHEAST_1",
  AWS_SES_AP_SOUTHEAST_2: "AWS_SES_AP_SOUTHEAST_2",
  AWS_SES_AP_SOUTHEAST_3: "AWS_SES_AP_SOUTHEAST_3",
  AWS_SES_AP_SOUTH_1: "AWS_SES_AP_SOUTH_1",
  AWS_SES_AP_SOUTH_2: "AWS_SES_AP_SOUTH_2",
  AWS_SES_CA_CENTRAL_1: "AWS_SES_CA_CENTRAL_1",
  AWS_SES_EU_CENTRAL_1: "AWS_SES_EU_CENTRAL_1",
  AWS_SES_EU_CENTRAL_2: "AWS_SES_EU_CENTRAL_2",
  AWS_SES_EU_NORTH_1: "AWS_SES_EU_NORTH_1",
  AWS_SES_EU_SOUTH_1: "AWS_SES_EU_SOUTH_1",
  AWS_SES_EU_WEST_1: "AWS_SES_EU_WEST_1",
  AWS_SES_EU_WEST_2: "AWS_SES_EU_WEST_2",
  AWS_SES_EU_WEST_3: "AWS_SES_EU_WEST_3",
  AWS_SES_IL_CENTRAL_1: "AWS_SES_IL_CENTRAL_1",
  AWS_SES_ME_CENTRAL_1: "AWS_SES_ME_CENTRAL_1",
  AWS_SES_ME_SOUTH_1: "AWS_SES_ME_SOUTH_1",
  AWS_SES_SA_EAST_1: "AWS_SES_SA_EAST_1",
  AWS_SES_US_EAST_1: "AWS_SES_US_EAST_1",
  AWS_SES_US_EAST_2: "AWS_SES_US_EAST_2",
  AWS_SES_US_WEST_1: "AWS_SES_US_WEST_1",
  AWS_SES_US_WEST_2: "AWS_SES_US_WEST_2",
  EXTERNAL: "EXTERNAL"
};
var DkimSigningKeyLength = {
  RSA_1024_BIT: "RSA_1024_BIT",
  RSA_2048_BIT: "RSA_2048_BIT"
};
var DkimStatus = {
  FAILED: "FAILED",
  NOT_STARTED: "NOT_STARTED",
  PENDING: "PENDING",
  SUCCESS: "SUCCESS",
  TEMPORARY_FAILURE: "TEMPORARY_FAILURE"
};
var IdentityType = {
  DOMAIN: "DOMAIN",
  EMAIL_ADDRESS: "EMAIL_ADDRESS",
  MANAGED_DOMAIN: "MANAGED_DOMAIN"
};
var DeliveryEventType = {
  COMPLAINT: "COMPLAINT",
  DELIVERY: "DELIVERY",
  PERMANENT_BOUNCE: "PERMANENT_BOUNCE",
  SEND: "SEND",
  TRANSIENT_BOUNCE: "TRANSIENT_BOUNCE",
  UNDETERMINED_BOUNCE: "UNDETERMINED_BOUNCE"
};
var EngagementEventType = {
  CLICK: "CLICK",
  OPEN: "OPEN"
};
var MetricAggregation = {
  RATE: "RATE",
  VOLUME: "VOLUME"
};
var DataFormat = {
  CSV: "CSV",
  JSON: "JSON"
};
var SuppressionListImportAction = {
  DELETE: "DELETE",
  PUT: "PUT"
};
var Status = {
  CREATING: "CREATING",
  DELETING: "DELETING",
  FAILED: "FAILED",
  READY: "READY"
};
var SendingStatus = {
  DISABLED: "DISABLED",
  ENABLED: "ENABLED",
  REINSTATED: "REINSTATED"
};
var WarmupStatus = {
  DONE: "DONE",
  IN_PROGRESS: "IN_PROGRESS",
  NOT_APPLICABLE: "NOT_APPLICABLE"
};
var DeliverabilityDashboardAccountStatus = {
  ACTIVE: "ACTIVE",
  DISABLED: "DISABLED",
  PENDING_EXPIRATION: "PENDING_EXPIRATION"
};
var ExportSourceType = {
  MESSAGE_INSIGHTS: "MESSAGE_INSIGHTS",
  METRICS_DATA: "METRICS_DATA"
};
var JobStatus = {
  CANCELLED: "CANCELLED",
  COMPLETED: "COMPLETED",
  CREATED: "CREATED",
  FAILED: "FAILED",
  PROCESSING: "PROCESSING"
};
var MailFromDomainStatus = {
  FAILED: "FAILED",
  PENDING: "PENDING",
  SUCCESS: "SUCCESS",
  TEMPORARY_FAILURE: "TEMPORARY_FAILURE"
};
var VerificationError = {
  DNS_SERVER_ERROR: "DNS_SERVER_ERROR",
  HOST_NOT_FOUND: "HOST_NOT_FOUND",
  INVALID_VALUE: "INVALID_VALUE",
  REPLICATION_ACCESS_DENIED: "REPLICATION_ACCESS_DENIED",
  REPLICATION_PRIMARY_BYO_DKIM_NOT_SUPPORTED: "REPLICATION_PRIMARY_BYO_DKIM_NOT_SUPPORTED",
  REPLICATION_PRIMARY_INVALID_REGION: "REPLICATION_PRIMARY_INVALID_REGION",
  REPLICATION_PRIMARY_NOT_FOUND: "REPLICATION_PRIMARY_NOT_FOUND",
  REPLICATION_REPLICA_AS_PRIMARY_NOT_SUPPORTED: "REPLICATION_REPLICA_AS_PRIMARY_NOT_SUPPORTED",
  SERVICE_ERROR: "SERVICE_ERROR",
  TYPE_NOT_FOUND: "TYPE_NOT_FOUND"
};
var VerificationStatus = {
  FAILED: "FAILED",
  NOT_STARTED: "NOT_STARTED",
  PENDING: "PENDING",
  SUCCESS: "SUCCESS",
  TEMPORARY_FAILURE: "TEMPORARY_FAILURE"
};
var ReputationEntityType = {
  RESOURCE: "RESOURCE"
};
var RecommendationImpact = {
  HIGH: "HIGH",
  LOW: "LOW"
};
var ImportDestinationType = {
  CONTACT_LIST: "CONTACT_LIST",
  SUPPRESSION_LIST: "SUPPRESSION_LIST"
};
var InvalidNextTokenException = class _InvalidNextTokenException extends SESv2ServiceException {
  static {
    __name(this, "InvalidNextTokenException");
  }
  name = "InvalidNextTokenException";
  $fault = "client";
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "InvalidNextTokenException",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _InvalidNextTokenException.prototype);
  }
};
var ListRecommendationsFilterKey = {
  IMPACT: "IMPACT",
  RESOURCE_ARN: "RESOURCE_ARN",
  STATUS: "STATUS",
  TYPE: "TYPE"
};
var RecommendationStatus = {
  FIXED: "FIXED",
  OPEN: "OPEN"
};
var RecommendationType = {
  BIMI: "BIMI",
  BOUNCE: "BOUNCE",
  COMPLAINT: "COMPLAINT",
  DKIM: "DKIM",
  DMARC: "DMARC",
  FEEDBACK_3P: "FEEDBACK_3P",
  IP_LISTING: "IP_LISTING",
  SPF: "SPF"
};
var ReputationEntityFilterKey = {
  ENTITY_REFERENCE_PREFIX: "ENTITY_REFERENCE_PREFIX",
  ENTITY_TYPE: "ENTITY_TYPE",
  REPUTATION_IMPACT: "REPUTATION_IMPACT",
  STATUS: "SENDING_STATUS"
};
var AccountDetailsFilterSensitiveLog = /* @__PURE__ */ __name((obj) => ({
  ...obj,
  ...obj.WebsiteURL && { WebsiteURL: import_smithy_client.SENSITIVE_STRING },
  ...obj.UseCaseDescription && { UseCaseDescription: import_smithy_client.SENSITIVE_STRING },
  ...obj.AdditionalContactEmailAddresses && { AdditionalContactEmailAddresses: import_smithy_client.SENSITIVE_STRING }
}), "AccountDetailsFilterSensitiveLog");
var DkimSigningAttributesFilterSensitiveLog = /* @__PURE__ */ __name((obj) => ({
  ...obj,
  ...obj.DomainSigningPrivateKey && { DomainSigningPrivateKey: import_smithy_client.SENSITIVE_STRING }
}), "DkimSigningAttributesFilterSensitiveLog");
var CreateEmailIdentityRequestFilterSensitiveLog = /* @__PURE__ */ __name((obj) => ({
  ...obj,
  ...obj.DkimSigningAttributes && {
    DkimSigningAttributes: DkimSigningAttributesFilterSensitiveLog(obj.DkimSigningAttributes)
  }
}), "CreateEmailIdentityRequestFilterSensitiveLog");
var MessageInsightsFiltersFilterSensitiveLog = /* @__PURE__ */ __name((obj) => ({
  ...obj,
  ...obj.FromEmailAddress && { FromEmailAddress: import_smithy_client.SENSITIVE_STRING },
  ...obj.Destination && { Destination: import_smithy_client.SENSITIVE_STRING },
  ...obj.Subject && { Subject: import_smithy_client.SENSITIVE_STRING }
}), "MessageInsightsFiltersFilterSensitiveLog");
var MessageInsightsDataSourceFilterSensitiveLog = /* @__PURE__ */ __name((obj) => ({
  ...obj,
  ...obj.Include && { Include: MessageInsightsFiltersFilterSensitiveLog(obj.Include) },
  ...obj.Exclude && { Exclude: MessageInsightsFiltersFilterSensitiveLog(obj.Exclude) }
}), "MessageInsightsDataSourceFilterSensitiveLog");
var ExportDataSourceFilterSensitiveLog = /* @__PURE__ */ __name((obj) => ({
  ...obj,
  ...obj.MessageInsightsDataSource && {
    MessageInsightsDataSource: MessageInsightsDataSourceFilterSensitiveLog(obj.MessageInsightsDataSource)
  }
}), "ExportDataSourceFilterSensitiveLog");
var CreateExportJobRequestFilterSensitiveLog = /* @__PURE__ */ __name((obj) => ({
  ...obj,
  ...obj.ExportDataSource && { ExportDataSource: ExportDataSourceFilterSensitiveLog(obj.ExportDataSource) }
}), "CreateExportJobRequestFilterSensitiveLog");
var EmailInsightsFilterSensitiveLog = /* @__PURE__ */ __name((obj) => ({
  ...obj,
  ...obj.Destination && { Destination: import_smithy_client.SENSITIVE_STRING }
}), "EmailInsightsFilterSensitiveLog");
var GetAccountResponseFilterSensitiveLog = /* @__PURE__ */ __name((obj) => ({
  ...obj,
  ...obj.Details && { Details: AccountDetailsFilterSensitiveLog(obj.Details) }
}), "GetAccountResponseFilterSensitiveLog");
var GetExportJobResponseFilterSensitiveLog = /* @__PURE__ */ __name((obj) => ({
  ...obj,
  ...obj.ExportDataSource && { ExportDataSource: ExportDataSourceFilterSensitiveLog(obj.ExportDataSource) }
}), "GetExportJobResponseFilterSensitiveLog");
var GetMessageInsightsResponseFilterSensitiveLog = /* @__PURE__ */ __name((obj) => ({
  ...obj,
  ...obj.FromEmailAddress && { FromEmailAddress: import_smithy_client.SENSITIVE_STRING },
  ...obj.Subject && { Subject: import_smithy_client.SENSITIVE_STRING },
  ...obj.Insights && { Insights: obj.Insights.map((item) => EmailInsightsFilterSensitiveLog(item)) }
}), "GetMessageInsightsResponseFilterSensitiveLog");

// src/protocols/Aws_restJson1.ts
var se_BatchGetMetricDataCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {
    "content-type": "application/json"
  };
  b.bp("/v2/email/metrics/batch");
  let body;
  body = JSON.stringify(
    (0, import_smithy_client.take)(input, {
      Queries: /* @__PURE__ */ __name((_) => se_BatchGetMetricDataQueries(_, context), "Queries")
    })
  );
  b.m("POST").h(headers).b(body);
  return b.build();
}, "se_BatchGetMetricDataCommand");
var se_CancelExportJobCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {};
  b.bp("/v2/email/export-jobs/{JobId}/cancel");
  b.p("JobId", () => input.JobId, "{JobId}", false);
  let body;
  b.m("PUT").h(headers).b(body);
  return b.build();
}, "se_CancelExportJobCommand");
var se_CreateConfigurationSetCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {
    "content-type": "application/json"
  };
  b.bp("/v2/email/configuration-sets");
  let body;
  body = JSON.stringify(
    (0, import_smithy_client.take)(input, {
      ArchivingOptions: /* @__PURE__ */ __name((_) => (0, import_smithy_client._json)(_), "ArchivingOptions"),
      ConfigurationSetName: [],
      DeliveryOptions: /* @__PURE__ */ __name((_) => (0, import_smithy_client._json)(_), "DeliveryOptions"),
      ReputationOptions: /* @__PURE__ */ __name((_) => se_ReputationOptions(_, context), "ReputationOptions"),
      SendingOptions: /* @__PURE__ */ __name((_) => (0, import_smithy_client._json)(_), "SendingOptions"),
      SuppressionOptions: /* @__PURE__ */ __name((_) => (0, import_smithy_client._json)(_), "SuppressionOptions"),
      Tags: /* @__PURE__ */ __name((_) => (0, import_smithy_client._json)(_), "Tags"),
      TrackingOptions: /* @__PURE__ */ __name((_) => (0, import_smithy_client._json)(_), "TrackingOptions"),
      VdmOptions: /* @__PURE__ */ __name((_) => (0, import_smithy_client._json)(_), "VdmOptions")
    })
  );
  b.m("POST").h(headers).b(body);
  return b.build();
}, "se_CreateConfigurationSetCommand");
var se_CreateConfigurationSetEventDestinationCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {
    "content-type": "application/json"
  };
  b.bp("/v2/email/configuration-sets/{ConfigurationSetName}/event-destinations");
  b.p("ConfigurationSetName", () => input.ConfigurationSetName, "{ConfigurationSetName}", false);
  let body;
  body = JSON.stringify(
    (0, import_smithy_client.take)(input, {
      EventDestination: /* @__PURE__ */ __name((_) => (0, import_smithy_client._json)(_), "EventDestination"),
      EventDestinationName: []
    })
  );
  b.m("POST").h(headers).b(body);
  return b.build();
}, "se_CreateConfigurationSetEventDestinationCommand");
var se_CreateContactCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {
    "content-type": "application/json"
  };
  b.bp("/v2/email/contact-lists/{ContactListName}/contacts");
  b.p("ContactListName", () => input.ContactListName, "{ContactListName}", false);
  let body;
  body = JSON.stringify(
    (0, import_smithy_client.take)(input, {
      AttributesData: [],
      EmailAddress: [],
      TopicPreferences: /* @__PURE__ */ __name((_) => (0, import_smithy_client._json)(_), "TopicPreferences"),
      UnsubscribeAll: []
    })
  );
  b.m("POST").h(headers).b(body);
  return b.build();
}, "se_CreateContactCommand");
var se_CreateContactListCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {
    "content-type": "application/json"
  };
  b.bp("/v2/email/contact-lists");
  let body;
  body = JSON.stringify(
    (0, import_smithy_client.take)(input, {
      ContactListName: [],
      Description: [],
      Tags: /* @__PURE__ */ __name((_) => (0, import_smithy_client._json)(_), "Tags"),
      Topics: /* @__PURE__ */ __name((_) => (0, import_smithy_client._json)(_), "Topics")
    })
  );
  b.m("POST").h(headers).b(body);
  return b.build();
}, "se_CreateContactListCommand");
var se_CreateCustomVerificationEmailTemplateCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {
    "content-type": "application/json"
  };
  b.bp("/v2/email/custom-verification-email-templates");
  let body;
  body = JSON.stringify(
    (0, import_smithy_client.take)(input, {
      FailureRedirectionURL: [],
      FromEmailAddress: [],
      SuccessRedirectionURL: [],
      TemplateContent: [],
      TemplateName: [],
      TemplateSubject: []
    })
  );
  b.m("POST").h(headers).b(body);
  return b.build();
}, "se_CreateCustomVerificationEmailTemplateCommand");
var se_CreateDedicatedIpPoolCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {
    "content-type": "application/json"
  };
  b.bp("/v2/email/dedicated-ip-pools");
  let body;
  body = JSON.stringify(
    (0, import_smithy_client.take)(input, {
      PoolName: [],
      ScalingMode: [],
      Tags: /* @__PURE__ */ __name((_) => (0, import_smithy_client._json)(_), "Tags")
    })
  );
  b.m("POST").h(headers).b(body);
  return b.build();
}, "se_CreateDedicatedIpPoolCommand");
var se_CreateDeliverabilityTestReportCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {
    "content-type": "application/json"
  };
  b.bp("/v2/email/deliverability-dashboard/test");
  let body;
  body = JSON.stringify(
    (0, import_smithy_client.take)(input, {
      Content: /* @__PURE__ */ __name((_) => se_EmailContent(_, context), "Content"),
      FromEmailAddress: [],
      ReportName: [],
      Tags: /* @__PURE__ */ __name((_) => (0, import_smithy_client._json)(_), "Tags")
    })
  );
  b.m("POST").h(headers).b(body);
  return b.build();
}, "se_CreateDeliverabilityTestReportCommand");
var se_CreateEmailIdentityCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {
    "content-type": "application/json"
  };
  b.bp("/v2/email/identities");
  let body;
  body = JSON.stringify(
    (0, import_smithy_client.take)(input, {
      ConfigurationSetName: [],
      DkimSigningAttributes: /* @__PURE__ */ __name((_) => (0, import_smithy_client._json)(_), "DkimSigningAttributes"),
      EmailIdentity: [],
      Tags: /* @__PURE__ */ __name((_) => (0, import_smithy_client._json)(_), "Tags")
    })
  );
  b.m("POST").h(headers).b(body);
  return b.build();
}, "se_CreateEmailIdentityCommand");
var se_CreateEmailIdentityPolicyCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {
    "content-type": "application/json"
  };
  b.bp("/v2/email/identities/{EmailIdentity}/policies/{PolicyName}");
  b.p("EmailIdentity", () => input.EmailIdentity, "{EmailIdentity}", false);
  b.p("PolicyName", () => input.PolicyName, "{PolicyName}", false);
  let body;
  body = JSON.stringify(
    (0, import_smithy_client.take)(input, {
      Policy: []
    })
  );
  b.m("POST").h(headers).b(body);
  return b.build();
}, "se_CreateEmailIdentityPolicyCommand");
var se_CreateEmailTemplateCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {
    "content-type": "application/json"
  };
  b.bp("/v2/email/templates");
  let body;
  body = JSON.stringify(
    (0, import_smithy_client.take)(input, {
      TemplateContent: /* @__PURE__ */ __name((_) => (0, import_smithy_client._json)(_), "TemplateContent"),
      TemplateName: []
    })
  );
  b.m("POST").h(headers).b(body);
  return b.build();
}, "se_CreateEmailTemplateCommand");
var se_CreateExportJobCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {
    "content-type": "application/json"
  };
  b.bp("/v2/email/export-jobs");
  let body;
  body = JSON.stringify(
    (0, import_smithy_client.take)(input, {
      ExportDataSource: /* @__PURE__ */ __name((_) => se_ExportDataSource(_, context), "ExportDataSource"),
      ExportDestination: /* @__PURE__ */ __name((_) => (0, import_smithy_client._json)(_), "ExportDestination")
    })
  );
  b.m("POST").h(headers).b(body);
  return b.build();
}, "se_CreateExportJobCommand");
var se_CreateImportJobCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {
    "content-type": "application/json"
  };
  b.bp("/v2/email/import-jobs");
  let body;
  body = JSON.stringify(
    (0, import_smithy_client.take)(input, {
      ImportDataSource: /* @__PURE__ */ __name((_) => (0, import_smithy_client._json)(_), "ImportDataSource"),
      ImportDestination: /* @__PURE__ */ __name((_) => (0, import_smithy_client._json)(_), "ImportDestination")
    })
  );
  b.m("POST").h(headers).b(body);
  return b.build();
}, "se_CreateImportJobCommand");
var se_CreateMultiRegionEndpointCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {
    "content-type": "application/json"
  };
  b.bp("/v2/email/multi-region-endpoints");
  let body;
  body = JSON.stringify(
    (0, import_smithy_client.take)(input, {
      Details: /* @__PURE__ */ __name((_) => (0, import_smithy_client._json)(_), "Details"),
      EndpointName: [],
      Tags: /* @__PURE__ */ __name((_) => (0, import_smithy_client._json)(_), "Tags")
    })
  );
  b.m("POST").h(headers).b(body);
  return b.build();
}, "se_CreateMultiRegionEndpointCommand");
var se_CreateTenantCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {
    "content-type": "application/json"
  };
  b.bp("/v2/email/tenants");
  let body;
  body = JSON.stringify(
    (0, import_smithy_client.take)(input, {
      Tags: /* @__PURE__ */ __name((_) => (0, import_smithy_client._json)(_), "Tags"),
      TenantName: []
    })
  );
  b.m("POST").h(headers).b(body);
  return b.build();
}, "se_CreateTenantCommand");
var se_CreateTenantResourceAssociationCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {
    "content-type": "application/json"
  };
  b.bp("/v2/email/tenants/resources");
  let body;
  body = JSON.stringify(
    (0, import_smithy_client.take)(input, {
      ResourceArn: [],
      TenantName: []
    })
  );
  b.m("POST").h(headers).b(body);
  return b.build();
}, "se_CreateTenantResourceAssociationCommand");
var se_DeleteConfigurationSetCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {};
  b.bp("/v2/email/configuration-sets/{ConfigurationSetName}");
  b.p("ConfigurationSetName", () => input.ConfigurationSetName, "{ConfigurationSetName}", false);
  let body;
  b.m("DELETE").h(headers).b(body);
  return b.build();
}, "se_DeleteConfigurationSetCommand");
var se_DeleteConfigurationSetEventDestinationCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {};
  b.bp("/v2/email/configuration-sets/{ConfigurationSetName}/event-destinations/{EventDestinationName}");
  b.p("ConfigurationSetName", () => input.ConfigurationSetName, "{ConfigurationSetName}", false);
  b.p("EventDestinationName", () => input.EventDestinationName, "{EventDestinationName}", false);
  let body;
  b.m("DELETE").h(headers).b(body);
  return b.build();
}, "se_DeleteConfigurationSetEventDestinationCommand");
var se_DeleteContactCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {};
  b.bp("/v2/email/contact-lists/{ContactListName}/contacts/{EmailAddress}");
  b.p("ContactListName", () => input.ContactListName, "{ContactListName}", false);
  b.p("EmailAddress", () => input.EmailAddress, "{EmailAddress}", false);
  let body;
  b.m("DELETE").h(headers).b(body);
  return b.build();
}, "se_DeleteContactCommand");
var se_DeleteContactListCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {};
  b.bp("/v2/email/contact-lists/{ContactListName}");
  b.p("ContactListName", () => input.ContactListName, "{ContactListName}", false);
  let body;
  b.m("DELETE").h(headers).b(body);
  return b.build();
}, "se_DeleteContactListCommand");
var se_DeleteCustomVerificationEmailTemplateCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {};
  b.bp("/v2/email/custom-verification-email-templates/{TemplateName}");
  b.p("TemplateName", () => input.TemplateName, "{TemplateName}", false);
  let body;
  b.m("DELETE").h(headers).b(body);
  return b.build();
}, "se_DeleteCustomVerificationEmailTemplateCommand");
var se_DeleteDedicatedIpPoolCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {};
  b.bp("/v2/email/dedicated-ip-pools/{PoolName}");
  b.p("PoolName", () => input.PoolName, "{PoolName}", false);
  let body;
  b.m("DELETE").h(headers).b(body);
  return b.build();
}, "se_DeleteDedicatedIpPoolCommand");
var se_DeleteEmailIdentityCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {};
  b.bp("/v2/email/identities/{EmailIdentity}");
  b.p("EmailIdentity", () => input.EmailIdentity, "{EmailIdentity}", false);
  let body;
  b.m("DELETE").h(headers).b(body);
  return b.build();
}, "se_DeleteEmailIdentityCommand");
var se_DeleteEmailIdentityPolicyCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {};
  b.bp("/v2/email/identities/{EmailIdentity}/policies/{PolicyName}");
  b.p("EmailIdentity", () => input.EmailIdentity, "{EmailIdentity}", false);
  b.p("PolicyName", () => input.PolicyName, "{PolicyName}", false);
  let body;
  b.m("DELETE").h(headers).b(body);
  return b.build();
}, "se_DeleteEmailIdentityPolicyCommand");
var se_DeleteEmailTemplateCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {};
  b.bp("/v2/email/templates/{TemplateName}");
  b.p("TemplateName", () => input.TemplateName, "{TemplateName}", false);
  let body;
  b.m("DELETE").h(headers).b(body);
  return b.build();
}, "se_DeleteEmailTemplateCommand");
var se_DeleteMultiRegionEndpointCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {};
  b.bp("/v2/email/multi-region-endpoints/{EndpointName}");
  b.p("EndpointName", () => input.EndpointName, "{EndpointName}", false);
  let body;
  b.m("DELETE").h(headers).b(body);
  return b.build();
}, "se_DeleteMultiRegionEndpointCommand");
var se_DeleteSuppressedDestinationCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {};
  b.bp("/v2/email/suppression/addresses/{EmailAddress}");
  b.p("EmailAddress", () => input.EmailAddress, "{EmailAddress}", false);
  let body;
  b.m("DELETE").h(headers).b(body);
  return b.build();
}, "se_DeleteSuppressedDestinationCommand");
var se_DeleteTenantCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {
    "content-type": "application/json"
  };
  b.bp("/v2/email/tenants/delete");
  let body;
  body = JSON.stringify(
    (0, import_smithy_client.take)(input, {
      TenantName: []
    })
  );
  b.m("POST").h(headers).b(body);
  return b.build();
}, "se_DeleteTenantCommand");
var se_DeleteTenantResourceAssociationCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {
    "content-type": "application/json"
  };
  b.bp("/v2/email/tenants/resources/delete");
  let body;
  body = JSON.stringify(
    (0, import_smithy_client.take)(input, {
      ResourceArn: [],
      TenantName: []
    })
  );
  b.m("POST").h(headers).b(body);
  return b.build();
}, "se_DeleteTenantResourceAssociationCommand");
var se_GetAccountCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {};
  b.bp("/v2/email/account");
  let body;
  b.m("GET").h(headers).b(body);
  return b.build();
}, "se_GetAccountCommand");
var se_GetBlacklistReportsCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {};
  b.bp("/v2/email/deliverability-dashboard/blacklist-report");
  const query = (0, import_smithy_client.map)({
    [_BIN]: [(0, import_smithy_client.expectNonNull)(input.BlacklistItemNames, `BlacklistItemNames`) != null, () => input[_BIN] || []]
  });
  let body;
  b.m("GET").h(headers).q(query).b(body);
  return b.build();
}, "se_GetBlacklistReportsCommand");
var se_GetConfigurationSetCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {};
  b.bp("/v2/email/configuration-sets/{ConfigurationSetName}");
  b.p("ConfigurationSetName", () => input.ConfigurationSetName, "{ConfigurationSetName}", false);
  let body;
  b.m("GET").h(headers).b(body);
  return b.build();
}, "se_GetConfigurationSetCommand");
var se_GetConfigurationSetEventDestinationsCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {};
  b.bp("/v2/email/configuration-sets/{ConfigurationSetName}/event-destinations");
  b.p("ConfigurationSetName", () => input.ConfigurationSetName, "{ConfigurationSetName}", false);
  let body;
  b.m("GET").h(headers).b(body);
  return b.build();
}, "se_GetConfigurationSetEventDestinationsCommand");
var se_GetContactCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {};
  b.bp("/v2/email/contact-lists/{ContactListName}/contacts/{EmailAddress}");
  b.p("ContactListName", () => input.ContactListName, "{ContactListName}", false);
  b.p("EmailAddress", () => input.EmailAddress, "{EmailAddress}", false);
  let body;
  b.m("GET").h(headers).b(body);
  return b.build();
}, "se_GetContactCommand");
var se_GetContactListCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {};
  b.bp("/v2/email/contact-lists/{ContactListName}");
  b.p("ContactListName", () => input.ContactListName, "{ContactListName}", false);
  let body;
  b.m("GET").h(headers).b(body);
  return b.build();
}, "se_GetContactListCommand");
var se_GetCustomVerificationEmailTemplateCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {};
  b.bp("/v2/email/custom-verification-email-templates/{TemplateName}");
  b.p("TemplateName", () => input.TemplateName, "{TemplateName}", false);
  let body;
  b.m("GET").h(headers).b(body);
  return b.build();
}, "se_GetCustomVerificationEmailTemplateCommand");
var se_GetDedicatedIpCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {};
  b.bp("/v2/email/dedicated-ips/{Ip}");
  b.p("Ip", () => input.Ip, "{Ip}", false);
  let body;
  b.m("GET").h(headers).b(body);
  return b.build();
}, "se_GetDedicatedIpCommand");
var se_GetDedicatedIpPoolCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {};
  b.bp("/v2/email/dedicated-ip-pools/{PoolName}");
  b.p("PoolName", () => input.PoolName, "{PoolName}", false);
  let body;
  b.m("GET").h(headers).b(body);
  return b.build();
}, "se_GetDedicatedIpPoolCommand");
var se_GetDedicatedIpsCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {};
  b.bp("/v2/email/dedicated-ips");
  const query = (0, import_smithy_client.map)({
    [_PN]: [, input[_PN]],
    [_NT]: [, input[_NT]],
    [_PS]: [() => input.PageSize !== void 0, () => input[_PS].toString()]
  });
  let body;
  b.m("GET").h(headers).q(query).b(body);
  return b.build();
}, "se_GetDedicatedIpsCommand");
var se_GetDeliverabilityDashboardOptionsCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {};
  b.bp("/v2/email/deliverability-dashboard");
  let body;
  b.m("GET").h(headers).b(body);
  return b.build();
}, "se_GetDeliverabilityDashboardOptionsCommand");
var se_GetDeliverabilityTestReportCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {};
  b.bp("/v2/email/deliverability-dashboard/test-reports/{ReportId}");
  b.p("ReportId", () => input.ReportId, "{ReportId}", false);
  let body;
  b.m("GET").h(headers).b(body);
  return b.build();
}, "se_GetDeliverabilityTestReportCommand");
var se_GetDomainDeliverabilityCampaignCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {};
  b.bp("/v2/email/deliverability-dashboard/campaigns/{CampaignId}");
  b.p("CampaignId", () => input.CampaignId, "{CampaignId}", false);
  let body;
  b.m("GET").h(headers).b(body);
  return b.build();
}, "se_GetDomainDeliverabilityCampaignCommand");
var se_GetDomainStatisticsReportCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {};
  b.bp("/v2/email/deliverability-dashboard/statistics-report/{Domain}");
  b.p("Domain", () => input.Domain, "{Domain}", false);
  const query = (0, import_smithy_client.map)({
    [_SD]: [(0, import_smithy_client.expectNonNull)(input.StartDate, `StartDate`) != null, () => (0, import_smithy_client.serializeDateTime)(input[_SD]).toString()],
    [_ED]: [(0, import_smithy_client.expectNonNull)(input.EndDate, `EndDate`) != null, () => (0, import_smithy_client.serializeDateTime)(input[_ED]).toString()]
  });
  let body;
  b.m("GET").h(headers).q(query).b(body);
  return b.build();
}, "se_GetDomainStatisticsReportCommand");
var se_GetEmailIdentityCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {};
  b.bp("/v2/email/identities/{EmailIdentity}");
  b.p("EmailIdentity", () => input.EmailIdentity, "{EmailIdentity}", false);
  let body;
  b.m("GET").h(headers).b(body);
  return b.build();
}, "se_GetEmailIdentityCommand");
var se_GetEmailIdentityPoliciesCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {};
  b.bp("/v2/email/identities/{EmailIdentity}/policies");
  b.p("EmailIdentity", () => input.EmailIdentity, "{EmailIdentity}", false);
  let body;
  b.m("GET").h(headers).b(body);
  return b.build();
}, "se_GetEmailIdentityPoliciesCommand");
var se_GetEmailTemplateCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {};
  b.bp("/v2/email/templates/{TemplateName}");
  b.p("TemplateName", () => input.TemplateName, "{TemplateName}", false);
  let body;
  b.m("GET").h(headers).b(body);
  return b.build();
}, "se_GetEmailTemplateCommand");
var se_GetExportJobCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {};
  b.bp("/v2/email/export-jobs/{JobId}");
  b.p("JobId", () => input.JobId, "{JobId}", false);
  let body;
  b.m("GET").h(headers).b(body);
  return b.build();
}, "se_GetExportJobCommand");
var se_GetImportJobCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {};
  b.bp("/v2/email/import-jobs/{JobId}");
  b.p("JobId", () => input.JobId, "{JobId}", false);
  let body;
  b.m("GET").h(headers).b(body);
  return b.build();
}, "se_GetImportJobCommand");
var se_GetMessageInsightsCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {};
  b.bp("/v2/email/insights/{MessageId}");
  b.p("MessageId", () => input.MessageId, "{MessageId}", false);
  let body;
  b.m("GET").h(headers).b(body);
  return b.build();
}, "se_GetMessageInsightsCommand");
var se_GetMultiRegionEndpointCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {};
  b.bp("/v2/email/multi-region-endpoints/{EndpointName}");
  b.p("EndpointName", () => input.EndpointName, "{EndpointName}", false);
  let body;
  b.m("GET").h(headers).b(body);
  return b.build();
}, "se_GetMultiRegionEndpointCommand");
var se_GetReputationEntityCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {};
  b.bp("/v2/email/reputation/entities/{ReputationEntityType}/{ReputationEntityReference}");
  b.p("ReputationEntityReference", () => input.ReputationEntityReference, "{ReputationEntityReference}", false);
  b.p("ReputationEntityType", () => input.ReputationEntityType, "{ReputationEntityType}", false);
  let body;
  b.m("GET").h(headers).b(body);
  return b.build();
}, "se_GetReputationEntityCommand");
var se_GetSuppressedDestinationCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {};
  b.bp("/v2/email/suppression/addresses/{EmailAddress}");
  b.p("EmailAddress", () => input.EmailAddress, "{EmailAddress}", false);
  let body;
  b.m("GET").h(headers).b(body);
  return b.build();
}, "se_GetSuppressedDestinationCommand");
var se_GetTenantCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {
    "content-type": "application/json"
  };
  b.bp("/v2/email/tenants/get");
  let body;
  body = JSON.stringify(
    (0, import_smithy_client.take)(input, {
      TenantName: []
    })
  );
  b.m("POST").h(headers).b(body);
  return b.build();
}, "se_GetTenantCommand");
var se_ListConfigurationSetsCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {};
  b.bp("/v2/email/configuration-sets");
  const query = (0, import_smithy_client.map)({
    [_NT]: [, input[_NT]],
    [_PS]: [() => input.PageSize !== void 0, () => input[_PS].toString()]
  });
  let body;
  b.m("GET").h(headers).q(query).b(body);
  return b.build();
}, "se_ListConfigurationSetsCommand");
var se_ListContactListsCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {};
  b.bp("/v2/email/contact-lists");
  const query = (0, import_smithy_client.map)({
    [_PS]: [() => input.PageSize !== void 0, () => input[_PS].toString()],
    [_NT]: [, input[_NT]]
  });
  let body;
  b.m("GET").h(headers).q(query).b(body);
  return b.build();
}, "se_ListContactListsCommand");
var se_ListContactsCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {
    "content-type": "application/json"
  };
  b.bp("/v2/email/contact-lists/{ContactListName}/contacts/list");
  b.p("ContactListName", () => input.ContactListName, "{ContactListName}", false);
  let body;
  body = JSON.stringify(
    (0, import_smithy_client.take)(input, {
      Filter: /* @__PURE__ */ __name((_) => (0, import_smithy_client._json)(_), "Filter"),
      NextToken: [],
      PageSize: []
    })
  );
  b.m("POST").h(headers).b(body);
  return b.build();
}, "se_ListContactsCommand");
var se_ListCustomVerificationEmailTemplatesCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {};
  b.bp("/v2/email/custom-verification-email-templates");
  const query = (0, import_smithy_client.map)({
    [_NT]: [, input[_NT]],
    [_PS]: [() => input.PageSize !== void 0, () => input[_PS].toString()]
  });
  let body;
  b.m("GET").h(headers).q(query).b(body);
  return b.build();
}, "se_ListCustomVerificationEmailTemplatesCommand");
var se_ListDedicatedIpPoolsCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {};
  b.bp("/v2/email/dedicated-ip-pools");
  const query = (0, import_smithy_client.map)({
    [_NT]: [, input[_NT]],
    [_PS]: [() => input.PageSize !== void 0, () => input[_PS].toString()]
  });
  let body;
  b.m("GET").h(headers).q(query).b(body);
  return b.build();
}, "se_ListDedicatedIpPoolsCommand");
var se_ListDeliverabilityTestReportsCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {};
  b.bp("/v2/email/deliverability-dashboard/test-reports");
  const query = (0, import_smithy_client.map)({
    [_NT]: [, input[_NT]],
    [_PS]: [() => input.PageSize !== void 0, () => input[_PS].toString()]
  });
  let body;
  b.m("GET").h(headers).q(query).b(body);
  return b.build();
}, "se_ListDeliverabilityTestReportsCommand");
var se_ListDomainDeliverabilityCampaignsCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {};
  b.bp("/v2/email/deliverability-dashboard/domains/{SubscribedDomain}/campaigns");
  b.p("SubscribedDomain", () => input.SubscribedDomain, "{SubscribedDomain}", false);
  const query = (0, import_smithy_client.map)({
    [_SD]: [(0, import_smithy_client.expectNonNull)(input.StartDate, `StartDate`) != null, () => (0, import_smithy_client.serializeDateTime)(input[_SD]).toString()],
    [_ED]: [(0, import_smithy_client.expectNonNull)(input.EndDate, `EndDate`) != null, () => (0, import_smithy_client.serializeDateTime)(input[_ED]).toString()],
    [_NT]: [, input[_NT]],
    [_PS]: [() => input.PageSize !== void 0, () => input[_PS].toString()]
  });
  let body;
  b.m("GET").h(headers).q(query).b(body);
  return b.build();
}, "se_ListDomainDeliverabilityCampaignsCommand");
var se_ListEmailIdentitiesCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {};
  b.bp("/v2/email/identities");
  const query = (0, import_smithy_client.map)({
    [_NT]: [, input[_NT]],
    [_PS]: [() => input.PageSize !== void 0, () => input[_PS].toString()]
  });
  let body;
  b.m("GET").h(headers).q(query).b(body);
  return b.build();
}, "se_ListEmailIdentitiesCommand");
var se_ListEmailTemplatesCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {};
  b.bp("/v2/email/templates");
  const query = (0, import_smithy_client.map)({
    [_NT]: [, input[_NT]],
    [_PS]: [() => input.PageSize !== void 0, () => input[_PS].toString()]
  });
  let body;
  b.m("GET").h(headers).q(query).b(body);
  return b.build();
}, "se_ListEmailTemplatesCommand");
var se_ListExportJobsCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {
    "content-type": "application/json"
  };
  b.bp("/v2/email/list-export-jobs");
  let body;
  body = JSON.stringify(
    (0, import_smithy_client.take)(input, {
      ExportSourceType: [],
      JobStatus: [],
      NextToken: [],
      PageSize: []
    })
  );
  b.m("POST").h(headers).b(body);
  return b.build();
}, "se_ListExportJobsCommand");
var se_ListImportJobsCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {
    "content-type": "application/json"
  };
  b.bp("/v2/email/import-jobs/list");
  let body;
  body = JSON.stringify(
    (0, import_smithy_client.take)(input, {
      ImportDestinationType: [],
      NextToken: [],
      PageSize: []
    })
  );
  b.m("POST").h(headers).b(body);
  return b.build();
}, "se_ListImportJobsCommand");
var se_ListMultiRegionEndpointsCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {};
  b.bp("/v2/email/multi-region-endpoints");
  const query = (0, import_smithy_client.map)({
    [_NT]: [, input[_NT]],
    [_PS]: [() => input.PageSize !== void 0, () => input[_PS].toString()]
  });
  let body;
  b.m("GET").h(headers).q(query).b(body);
  return b.build();
}, "se_ListMultiRegionEndpointsCommand");
var se_ListRecommendationsCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {
    "content-type": "application/json"
  };
  b.bp("/v2/email/vdm/recommendations");
  let body;
  body = JSON.stringify(
    (0, import_smithy_client.take)(input, {
      Filter: /* @__PURE__ */ __name((_) => (0, import_smithy_client._json)(_), "Filter"),
      NextToken: [],
      PageSize: []
    })
  );
  b.m("POST").h(headers).b(body);
  return b.build();
}, "se_ListRecommendationsCommand");
var se_ListReputationEntitiesCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {
    "content-type": "application/json"
  };
  b.bp("/v2/email/reputation/entities");
  let body;
  body = JSON.stringify(
    (0, import_smithy_client.take)(input, {
      Filter: /* @__PURE__ */ __name((_) => (0, import_smithy_client._json)(_), "Filter"),
      NextToken: [],
      PageSize: []
    })
  );
  b.m("POST").h(headers).b(body);
  return b.build();
}, "se_ListReputationEntitiesCommand");
var se_ListResourceTenantsCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {
    "content-type": "application/json"
  };
  b.bp("/v2/email/resources/tenants/list");
  let body;
  body = JSON.stringify(
    (0, import_smithy_client.take)(input, {
      NextToken: [],
      PageSize: [],
      ResourceArn: []
    })
  );
  b.m("POST").h(headers).b(body);
  return b.build();
}, "se_ListResourceTenantsCommand");
var se_ListSuppressedDestinationsCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {};
  b.bp("/v2/email/suppression/addresses");
  const query = (0, import_smithy_client.map)({
    [_Re]: [() => input.Reasons !== void 0, () => input[_R] || []],
    [_SD]: [() => input.StartDate !== void 0, () => (0, import_smithy_client.serializeDateTime)(input[_SD]).toString()],
    [_ED]: [() => input.EndDate !== void 0, () => (0, import_smithy_client.serializeDateTime)(input[_ED]).toString()],
    [_NT]: [, input[_NT]],
    [_PS]: [() => input.PageSize !== void 0, () => input[_PS].toString()]
  });
  let body;
  b.m("GET").h(headers).q(query).b(body);
  return b.build();
}, "se_ListSuppressedDestinationsCommand");
var se_ListTagsForResourceCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {};
  b.bp("/v2/email/tags");
  const query = (0, import_smithy_client.map)({
    [_RA]: [, (0, import_smithy_client.expectNonNull)(input[_RA], `ResourceArn`)]
  });
  let body;
  b.m("GET").h(headers).q(query).b(body);
  return b.build();
}, "se_ListTagsForResourceCommand");
var se_ListTenantResourcesCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {
    "content-type": "application/json"
  };
  b.bp("/v2/email/tenants/resources/list");
  let body;
  body = JSON.stringify(
    (0, import_smithy_client.take)(input, {
      Filter: /* @__PURE__ */ __name((_) => (0, import_smithy_client._json)(_), "Filter"),
      NextToken: [],
      PageSize: [],
      TenantName: []
    })
  );
  b.m("POST").h(headers).b(body);
  return b.build();
}, "se_ListTenantResourcesCommand");
var se_ListTenantsCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {
    "content-type": "application/json"
  };
  b.bp("/v2/email/tenants/list");
  let body;
  body = JSON.stringify(
    (0, import_smithy_client.take)(input, {
      NextToken: [],
      PageSize: []
    })
  );
  b.m("POST").h(headers).b(body);
  return b.build();
}, "se_ListTenantsCommand");
var se_PutAccountDedicatedIpWarmupAttributesCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {
    "content-type": "application/json"
  };
  b.bp("/v2/email/account/dedicated-ips/warmup");
  let body;
  body = JSON.stringify(
    (0, import_smithy_client.take)(input, {
      AutoWarmupEnabled: []
    })
  );
  b.m("PUT").h(headers).b(body);
  return b.build();
}, "se_PutAccountDedicatedIpWarmupAttributesCommand");
var se_PutAccountDetailsCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {
    "content-type": "application/json"
  };
  b.bp("/v2/email/account/details");
  let body;
  body = JSON.stringify(
    (0, import_smithy_client.take)(input, {
      AdditionalContactEmailAddresses: /* @__PURE__ */ __name((_) => (0, import_smithy_client._json)(_), "AdditionalContactEmailAddresses"),
      ContactLanguage: [],
      MailType: [],
      ProductionAccessEnabled: [],
      UseCaseDescription: [],
      WebsiteURL: []
    })
  );
  b.m("POST").h(headers).b(body);
  return b.build();
}, "se_PutAccountDetailsCommand");
var se_PutAccountSendingAttributesCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {
    "content-type": "application/json"
  };
  b.bp("/v2/email/account/sending");
  let body;
  body = JSON.stringify(
    (0, import_smithy_client.take)(input, {
      SendingEnabled: []
    })
  );
  b.m("PUT").h(headers).b(body);
  return b.build();
}, "se_PutAccountSendingAttributesCommand");
var se_PutAccountSuppressionAttributesCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {
    "content-type": "application/json"
  };
  b.bp("/v2/email/account/suppression");
  let body;
  body = JSON.stringify(
    (0, import_smithy_client.take)(input, {
      SuppressedReasons: /* @__PURE__ */ __name((_) => (0, import_smithy_client._json)(_), "SuppressedReasons")
    })
  );
  b.m("PUT").h(headers).b(body);
  return b.build();
}, "se_PutAccountSuppressionAttributesCommand");
var se_PutAccountVdmAttributesCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {
    "content-type": "application/json"
  };
  b.bp("/v2/email/account/vdm");
  let body;
  body = JSON.stringify(
    (0, import_smithy_client.take)(input, {
      VdmAttributes: /* @__PURE__ */ __name((_) => (0, import_smithy_client._json)(_), "VdmAttributes")
    })
  );
  b.m("PUT").h(headers).b(body);
  return b.build();
}, "se_PutAccountVdmAttributesCommand");
var se_PutConfigurationSetArchivingOptionsCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {
    "content-type": "application/json"
  };
  b.bp("/v2/email/configuration-sets/{ConfigurationSetName}/archiving-options");
  b.p("ConfigurationSetName", () => input.ConfigurationSetName, "{ConfigurationSetName}", false);
  let body;
  body = JSON.stringify(
    (0, import_smithy_client.take)(input, {
      ArchiveArn: []
    })
  );
  b.m("PUT").h(headers).b(body);
  return b.build();
}, "se_PutConfigurationSetArchivingOptionsCommand");
var se_PutConfigurationSetDeliveryOptionsCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {
    "content-type": "application/json"
  };
  b.bp("/v2/email/configuration-sets/{ConfigurationSetName}/delivery-options");
  b.p("ConfigurationSetName", () => input.ConfigurationSetName, "{ConfigurationSetName}", false);
  let body;
  body = JSON.stringify(
    (0, import_smithy_client.take)(input, {
      MaxDeliverySeconds: [],
      SendingPoolName: [],
      TlsPolicy: []
    })
  );
  b.m("PUT").h(headers).b(body);
  return b.build();
}, "se_PutConfigurationSetDeliveryOptionsCommand");
var se_PutConfigurationSetReputationOptionsCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {
    "content-type": "application/json"
  };
  b.bp("/v2/email/configuration-sets/{ConfigurationSetName}/reputation-options");
  b.p("ConfigurationSetName", () => input.ConfigurationSetName, "{ConfigurationSetName}", false);
  let body;
  body = JSON.stringify(
    (0, import_smithy_client.take)(input, {
      ReputationMetricsEnabled: []
    })
  );
  b.m("PUT").h(headers).b(body);
  return b.build();
}, "se_PutConfigurationSetReputationOptionsCommand");
var se_PutConfigurationSetSendingOptionsCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {
    "content-type": "application/json"
  };
  b.bp("/v2/email/configuration-sets/{ConfigurationSetName}/sending");
  b.p("ConfigurationSetName", () => input.ConfigurationSetName, "{ConfigurationSetName}", false);
  let body;
  body = JSON.stringify(
    (0, import_smithy_client.take)(input, {
      SendingEnabled: []
    })
  );
  b.m("PUT").h(headers).b(body);
  return b.build();
}, "se_PutConfigurationSetSendingOptionsCommand");
var se_PutConfigurationSetSuppressionOptionsCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {
    "content-type": "application/json"
  };
  b.bp("/v2/email/configuration-sets/{ConfigurationSetName}/suppression-options");
  b.p("ConfigurationSetName", () => input.ConfigurationSetName, "{ConfigurationSetName}", false);
  let body;
  body = JSON.stringify(
    (0, import_smithy_client.take)(input, {
      SuppressedReasons: /* @__PURE__ */ __name((_) => (0, import_smithy_client._json)(_), "SuppressedReasons")
    })
  );
  b.m("PUT").h(headers).b(body);
  return b.build();
}, "se_PutConfigurationSetSuppressionOptionsCommand");
var se_PutConfigurationSetTrackingOptionsCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {
    "content-type": "application/json"
  };
  b.bp("/v2/email/configuration-sets/{ConfigurationSetName}/tracking-options");
  b.p("ConfigurationSetName", () => input.ConfigurationSetName, "{ConfigurationSetName}", false);
  let body;
  body = JSON.stringify(
    (0, import_smithy_client.take)(input, {
      CustomRedirectDomain: [],
      HttpsPolicy: []
    })
  );
  b.m("PUT").h(headers).b(body);
  return b.build();
}, "se_PutConfigurationSetTrackingOptionsCommand");
var se_PutConfigurationSetVdmOptionsCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {
    "content-type": "application/json"
  };
  b.bp("/v2/email/configuration-sets/{ConfigurationSetName}/vdm-options");
  b.p("ConfigurationSetName", () => input.ConfigurationSetName, "{ConfigurationSetName}", false);
  let body;
  body = JSON.stringify(
    (0, import_smithy_client.take)(input, {
      VdmOptions: /* @__PURE__ */ __name((_) => (0, import_smithy_client._json)(_), "VdmOptions")
    })
  );
  b.m("PUT").h(headers).b(body);
  return b.build();
}, "se_PutConfigurationSetVdmOptionsCommand");
var se_PutDedicatedIpInPoolCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {
    "content-type": "application/json"
  };
  b.bp("/v2/email/dedicated-ips/{Ip}/pool");
  b.p("Ip", () => input.Ip, "{Ip}", false);
  let body;
  body = JSON.stringify(
    (0, import_smithy_client.take)(input, {
      DestinationPoolName: []
    })
  );
  b.m("PUT").h(headers).b(body);
  return b.build();
}, "se_PutDedicatedIpInPoolCommand");
var se_PutDedicatedIpPoolScalingAttributesCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {
    "content-type": "application/json"
  };
  b.bp("/v2/email/dedicated-ip-pools/{PoolName}/scaling");
  b.p("PoolName", () => input.PoolName, "{PoolName}", false);
  let body;
  body = JSON.stringify(
    (0, import_smithy_client.take)(input, {
      ScalingMode: []
    })
  );
  b.m("PUT").h(headers).b(body);
  return b.build();
}, "se_PutDedicatedIpPoolScalingAttributesCommand");
var se_PutDedicatedIpWarmupAttributesCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {
    "content-type": "application/json"
  };
  b.bp("/v2/email/dedicated-ips/{Ip}/warmup");
  b.p("Ip", () => input.Ip, "{Ip}", false);
  let body;
  body = JSON.stringify(
    (0, import_smithy_client.take)(input, {
      WarmupPercentage: []
    })
  );
  b.m("PUT").h(headers).b(body);
  return b.build();
}, "se_PutDedicatedIpWarmupAttributesCommand");
var se_PutDeliverabilityDashboardOptionCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {
    "content-type": "application/json"
  };
  b.bp("/v2/email/deliverability-dashboard");
  let body;
  body = JSON.stringify(
    (0, import_smithy_client.take)(input, {
      DashboardEnabled: [],
      SubscribedDomains: /* @__PURE__ */ __name((_) => se_DomainDeliverabilityTrackingOptions(_, context), "SubscribedDomains")
    })
  );
  b.m("PUT").h(headers).b(body);
  return b.build();
}, "se_PutDeliverabilityDashboardOptionCommand");
var se_PutEmailIdentityConfigurationSetAttributesCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {
    "content-type": "application/json"
  };
  b.bp("/v2/email/identities/{EmailIdentity}/configuration-set");
  b.p("EmailIdentity", () => input.EmailIdentity, "{EmailIdentity}", false);
  let body;
  body = JSON.stringify(
    (0, import_smithy_client.take)(input, {
      ConfigurationSetName: []
    })
  );
  b.m("PUT").h(headers).b(body);
  return b.build();
}, "se_PutEmailIdentityConfigurationSetAttributesCommand");
var se_PutEmailIdentityDkimAttributesCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {
    "content-type": "application/json"
  };
  b.bp("/v2/email/identities/{EmailIdentity}/dkim");
  b.p("EmailIdentity", () => input.EmailIdentity, "{EmailIdentity}", false);
  let body;
  body = JSON.stringify(
    (0, import_smithy_client.take)(input, {
      SigningEnabled: []
    })
  );
  b.m("PUT").h(headers).b(body);
  return b.build();
}, "se_PutEmailIdentityDkimAttributesCommand");
var se_PutEmailIdentityDkimSigningAttributesCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {
    "content-type": "application/json"
  };
  b.bp("/v1/email/identities/{EmailIdentity}/dkim/signing");
  b.p("EmailIdentity", () => input.EmailIdentity, "{EmailIdentity}", false);
  let body;
  body = JSON.stringify(
    (0, import_smithy_client.take)(input, {
      SigningAttributes: /* @__PURE__ */ __name((_) => (0, import_smithy_client._json)(_), "SigningAttributes"),
      SigningAttributesOrigin: []
    })
  );
  b.m("PUT").h(headers).b(body);
  return b.build();
}, "se_PutEmailIdentityDkimSigningAttributesCommand");
var se_PutEmailIdentityFeedbackAttributesCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {
    "content-type": "application/json"
  };
  b.bp("/v2/email/identities/{EmailIdentity}/feedback");
  b.p("EmailIdentity", () => input.EmailIdentity, "{EmailIdentity}", false);
  let body;
  body = JSON.stringify(
    (0, import_smithy_client.take)(input, {
      EmailForwardingEnabled: []
    })
  );
  b.m("PUT").h(headers).b(body);
  return b.build();
}, "se_PutEmailIdentityFeedbackAttributesCommand");
var se_PutEmailIdentityMailFromAttributesCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {
    "content-type": "application/json"
  };
  b.bp("/v2/email/identities/{EmailIdentity}/mail-from");
  b.p("EmailIdentity", () => input.EmailIdentity, "{EmailIdentity}", false);
  let body;
  body = JSON.stringify(
    (0, import_smithy_client.take)(input, {
      BehaviorOnMxFailure: [],
      MailFromDomain: []
    })
  );
  b.m("PUT").h(headers).b(body);
  return b.build();
}, "se_PutEmailIdentityMailFromAttributesCommand");
var se_PutSuppressedDestinationCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {
    "content-type": "application/json"
  };
  b.bp("/v2/email/suppression/addresses");
  let body;
  body = JSON.stringify(
    (0, import_smithy_client.take)(input, {
      EmailAddress: [],
      Reason: []
    })
  );
  b.m("PUT").h(headers).b(body);
  return b.build();
}, "se_PutSuppressedDestinationCommand");
var se_SendBulkEmailCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {
    "content-type": "application/json"
  };
  b.bp("/v2/email/outbound-bulk-emails");
  let body;
  body = JSON.stringify(
    (0, import_smithy_client.take)(input, {
      BulkEmailEntries: /* @__PURE__ */ __name((_) => (0, import_smithy_client._json)(_), "BulkEmailEntries"),
      ConfigurationSetName: [],
      DefaultContent: /* @__PURE__ */ __name((_) => se_BulkEmailContent(_, context), "DefaultContent"),
      DefaultEmailTags: /* @__PURE__ */ __name((_) => (0, import_smithy_client._json)(_), "DefaultEmailTags"),
      EndpointId: [],
      FeedbackForwardingEmailAddress: [],
      FeedbackForwardingEmailAddressIdentityArn: [],
      FromEmailAddress: [],
      FromEmailAddressIdentityArn: [],
      ReplyToAddresses: /* @__PURE__ */ __name((_) => (0, import_smithy_client._json)(_), "ReplyToAddresses"),
      TenantName: []
    })
  );
  b.m("POST").h(headers).b(body);
  return b.build();
}, "se_SendBulkEmailCommand");
var se_SendCustomVerificationEmailCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {
    "content-type": "application/json"
  };
  b.bp("/v2/email/outbound-custom-verification-emails");
  let body;
  body = JSON.stringify(
    (0, import_smithy_client.take)(input, {
      ConfigurationSetName: [],
      EmailAddress: [],
      TemplateName: []
    })
  );
  b.m("POST").h(headers).b(body);
  return b.build();
}, "se_SendCustomVerificationEmailCommand");
var se_SendEmailCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {
    "content-type": "application/json"
  };
  b.bp("/v2/email/outbound-emails");
  let body;
  body = JSON.stringify(
    (0, import_smithy_client.take)(input, {
      ConfigurationSetName: [],
      Content: /* @__PURE__ */ __name((_) => se_EmailContent(_, context), "Content"),
      Destination: /* @__PURE__ */ __name((_) => (0, import_smithy_client._json)(_), "Destination"),
      EmailTags: /* @__PURE__ */ __name((_) => (0, import_smithy_client._json)(_), "EmailTags"),
      EndpointId: [],
      FeedbackForwardingEmailAddress: [],
      FeedbackForwardingEmailAddressIdentityArn: [],
      FromEmailAddress: [],
      FromEmailAddressIdentityArn: [],
      ListManagementOptions: /* @__PURE__ */ __name((_) => (0, import_smithy_client._json)(_), "ListManagementOptions"),
      ReplyToAddresses: /* @__PURE__ */ __name((_) => (0, import_smithy_client._json)(_), "ReplyToAddresses"),
      TenantName: []
    })
  );
  b.m("POST").h(headers).b(body);
  return b.build();
}, "se_SendEmailCommand");
var se_TagResourceCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {
    "content-type": "application/json"
  };
  b.bp("/v2/email/tags");
  let body;
  body = JSON.stringify(
    (0, import_smithy_client.take)(input, {
      ResourceArn: [],
      Tags: /* @__PURE__ */ __name((_) => (0, import_smithy_client._json)(_), "Tags")
    })
  );
  b.m("POST").h(headers).b(body);
  return b.build();
}, "se_TagResourceCommand");
var se_TestRenderEmailTemplateCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {
    "content-type": "application/json"
  };
  b.bp("/v2/email/templates/{TemplateName}/render");
  b.p("TemplateName", () => input.TemplateName, "{TemplateName}", false);
  let body;
  body = JSON.stringify(
    (0, import_smithy_client.take)(input, {
      TemplateData: []
    })
  );
  b.m("POST").h(headers).b(body);
  return b.build();
}, "se_TestRenderEmailTemplateCommand");
var se_UntagResourceCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {};
  b.bp("/v2/email/tags");
  const query = (0, import_smithy_client.map)({
    [_RA]: [, (0, import_smithy_client.expectNonNull)(input[_RA], `ResourceArn`)],
    [_TK]: [(0, import_smithy_client.expectNonNull)(input.TagKeys, `TagKeys`) != null, () => input[_TK] || []]
  });
  let body;
  b.m("DELETE").h(headers).q(query).b(body);
  return b.build();
}, "se_UntagResourceCommand");
var se_UpdateConfigurationSetEventDestinationCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {
    "content-type": "application/json"
  };
  b.bp("/v2/email/configuration-sets/{ConfigurationSetName}/event-destinations/{EventDestinationName}");
  b.p("ConfigurationSetName", () => input.ConfigurationSetName, "{ConfigurationSetName}", false);
  b.p("EventDestinationName", () => input.EventDestinationName, "{EventDestinationName}", false);
  let body;
  body = JSON.stringify(
    (0, import_smithy_client.take)(input, {
      EventDestination: /* @__PURE__ */ __name((_) => (0, import_smithy_client._json)(_), "EventDestination")
    })
  );
  b.m("PUT").h(headers).b(body);
  return b.build();
}, "se_UpdateConfigurationSetEventDestinationCommand");
var se_UpdateContactCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {
    "content-type": "application/json"
  };
  b.bp("/v2/email/contact-lists/{ContactListName}/contacts/{EmailAddress}");
  b.p("ContactListName", () => input.ContactListName, "{ContactListName}", false);
  b.p("EmailAddress", () => input.EmailAddress, "{EmailAddress}", false);
  let body;
  body = JSON.stringify(
    (0, import_smithy_client.take)(input, {
      AttributesData: [],
      TopicPreferences: /* @__PURE__ */ __name((_) => (0, import_smithy_client._json)(_), "TopicPreferences"),
      UnsubscribeAll: []
    })
  );
  b.m("PUT").h(headers).b(body);
  return b.build();
}, "se_UpdateContactCommand");
var se_UpdateContactListCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {
    "content-type": "application/json"
  };
  b.bp("/v2/email/contact-lists/{ContactListName}");
  b.p("ContactListName", () => input.ContactListName, "{ContactListName}", false);
  let body;
  body = JSON.stringify(
    (0, import_smithy_client.take)(input, {
      Description: [],
      Topics: /* @__PURE__ */ __name((_) => (0, import_smithy_client._json)(_), "Topics")
    })
  );
  b.m("PUT").h(headers).b(body);
  return b.build();
}, "se_UpdateContactListCommand");
var se_UpdateCustomVerificationEmailTemplateCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {
    "content-type": "application/json"
  };
  b.bp("/v2/email/custom-verification-email-templates/{TemplateName}");
  b.p("TemplateName", () => input.TemplateName, "{TemplateName}", false);
  let body;
  body = JSON.stringify(
    (0, import_smithy_client.take)(input, {
      FailureRedirectionURL: [],
      FromEmailAddress: [],
      SuccessRedirectionURL: [],
      TemplateContent: [],
      TemplateSubject: []
    })
  );
  b.m("PUT").h(headers).b(body);
  return b.build();
}, "se_UpdateCustomVerificationEmailTemplateCommand");
var se_UpdateEmailIdentityPolicyCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {
    "content-type": "application/json"
  };
  b.bp("/v2/email/identities/{EmailIdentity}/policies/{PolicyName}");
  b.p("EmailIdentity", () => input.EmailIdentity, "{EmailIdentity}", false);
  b.p("PolicyName", () => input.PolicyName, "{PolicyName}", false);
  let body;
  body = JSON.stringify(
    (0, import_smithy_client.take)(input, {
      Policy: []
    })
  );
  b.m("PUT").h(headers).b(body);
  return b.build();
}, "se_UpdateEmailIdentityPolicyCommand");
var se_UpdateEmailTemplateCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {
    "content-type": "application/json"
  };
  b.bp("/v2/email/templates/{TemplateName}");
  b.p("TemplateName", () => input.TemplateName, "{TemplateName}", false);
  let body;
  body = JSON.stringify(
    (0, import_smithy_client.take)(input, {
      TemplateContent: /* @__PURE__ */ __name((_) => (0, import_smithy_client._json)(_), "TemplateContent")
    })
  );
  b.m("PUT").h(headers).b(body);
  return b.build();
}, "se_UpdateEmailTemplateCommand");
var se_UpdateReputationEntityCustomerManagedStatusCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {
    "content-type": "application/json"
  };
  b.bp("/v2/email/reputation/entities/{ReputationEntityType}/{ReputationEntityReference}/customer-managed-status");
  b.p("ReputationEntityType", () => input.ReputationEntityType, "{ReputationEntityType}", false);
  b.p("ReputationEntityReference", () => input.ReputationEntityReference, "{ReputationEntityReference}", false);
  let body;
  body = JSON.stringify(
    (0, import_smithy_client.take)(input, {
      SendingStatus: []
    })
  );
  b.m("PUT").h(headers).b(body);
  return b.build();
}, "se_UpdateReputationEntityCustomerManagedStatusCommand");
var se_UpdateReputationEntityPolicyCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {
    "content-type": "application/json"
  };
  b.bp("/v2/email/reputation/entities/{ReputationEntityType}/{ReputationEntityReference}/policy");
  b.p("ReputationEntityType", () => input.ReputationEntityType, "{ReputationEntityType}", false);
  b.p("ReputationEntityReference", () => input.ReputationEntityReference, "{ReputationEntityReference}", false);
  let body;
  body = JSON.stringify(
    (0, import_smithy_client.take)(input, {
      ReputationEntityPolicy: []
    })
  );
  b.m("PUT").h(headers).b(body);
  return b.build();
}, "se_UpdateReputationEntityPolicyCommand");
var de_BatchGetMetricDataCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  const data = (0, import_smithy_client.expectNonNull)((0, import_smithy_client.expectObject)(await (0, import_core2.parseJsonBody)(output.body, context)), "body");
  const doc = (0, import_smithy_client.take)(data, {
    Errors: import_smithy_client._json,
    Results: /* @__PURE__ */ __name((_) => de_MetricDataResultList(_, context), "Results")
  });
  Object.assign(contents, doc);
  return contents;
}, "de_BatchGetMetricDataCommand");
var de_CancelExportJobCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  await (0, import_smithy_client.collectBody)(output.body, context);
  return contents;
}, "de_CancelExportJobCommand");
var de_CreateConfigurationSetCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  await (0, import_smithy_client.collectBody)(output.body, context);
  return contents;
}, "de_CreateConfigurationSetCommand");
var de_CreateConfigurationSetEventDestinationCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  await (0, import_smithy_client.collectBody)(output.body, context);
  return contents;
}, "de_CreateConfigurationSetEventDestinationCommand");
var de_CreateContactCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  await (0, import_smithy_client.collectBody)(output.body, context);
  return contents;
}, "de_CreateContactCommand");
var de_CreateContactListCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  await (0, import_smithy_client.collectBody)(output.body, context);
  return contents;
}, "de_CreateContactListCommand");
var de_CreateCustomVerificationEmailTemplateCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  await (0, import_smithy_client.collectBody)(output.body, context);
  return contents;
}, "de_CreateCustomVerificationEmailTemplateCommand");
var de_CreateDedicatedIpPoolCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  await (0, import_smithy_client.collectBody)(output.body, context);
  return contents;
}, "de_CreateDedicatedIpPoolCommand");
var de_CreateDeliverabilityTestReportCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  const data = (0, import_smithy_client.expectNonNull)((0, import_smithy_client.expectObject)(await (0, import_core2.parseJsonBody)(output.body, context)), "body");
  const doc = (0, import_smithy_client.take)(data, {
    DeliverabilityTestStatus: import_smithy_client.expectString,
    ReportId: import_smithy_client.expectString
  });
  Object.assign(contents, doc);
  return contents;
}, "de_CreateDeliverabilityTestReportCommand");
var de_CreateEmailIdentityCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  const data = (0, import_smithy_client.expectNonNull)((0, import_smithy_client.expectObject)(await (0, import_core2.parseJsonBody)(output.body, context)), "body");
  const doc = (0, import_smithy_client.take)(data, {
    DkimAttributes: /* @__PURE__ */ __name((_) => de_DkimAttributes(_, context), "DkimAttributes"),
    IdentityType: import_smithy_client.expectString,
    VerifiedForSendingStatus: import_smithy_client.expectBoolean
  });
  Object.assign(contents, doc);
  return contents;
}, "de_CreateEmailIdentityCommand");
var de_CreateEmailIdentityPolicyCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  await (0, import_smithy_client.collectBody)(output.body, context);
  return contents;
}, "de_CreateEmailIdentityPolicyCommand");
var de_CreateEmailTemplateCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  await (0, import_smithy_client.collectBody)(output.body, context);
  return contents;
}, "de_CreateEmailTemplateCommand");
var de_CreateExportJobCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  const data = (0, import_smithy_client.expectNonNull)((0, import_smithy_client.expectObject)(await (0, import_core2.parseJsonBody)(output.body, context)), "body");
  const doc = (0, import_smithy_client.take)(data, {
    JobId: import_smithy_client.expectString
  });
  Object.assign(contents, doc);
  return contents;
}, "de_CreateExportJobCommand");
var de_CreateImportJobCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  const data = (0, import_smithy_client.expectNonNull)((0, import_smithy_client.expectObject)(await (0, import_core2.parseJsonBody)(output.body, context)), "body");
  const doc = (0, import_smithy_client.take)(data, {
    JobId: import_smithy_client.expectString
  });
  Object.assign(contents, doc);
  return contents;
}, "de_CreateImportJobCommand");
var de_CreateMultiRegionEndpointCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  const data = (0, import_smithy_client.expectNonNull)((0, import_smithy_client.expectObject)(await (0, import_core2.parseJsonBody)(output.body, context)), "body");
  const doc = (0, import_smithy_client.take)(data, {
    EndpointId: import_smithy_client.expectString,
    Status: import_smithy_client.expectString
  });
  Object.assign(contents, doc);
  return contents;
}, "de_CreateMultiRegionEndpointCommand");
var de_CreateTenantCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  const data = (0, import_smithy_client.expectNonNull)((0, import_smithy_client.expectObject)(await (0, import_core2.parseJsonBody)(output.body, context)), "body");
  const doc = (0, import_smithy_client.take)(data, {
    CreatedTimestamp: /* @__PURE__ */ __name((_) => (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseEpochTimestamp)((0, import_smithy_client.expectNumber)(_))), "CreatedTimestamp"),
    SendingStatus: import_smithy_client.expectString,
    Tags: import_smithy_client._json,
    TenantArn: import_smithy_client.expectString,
    TenantId: import_smithy_client.expectString,
    TenantName: import_smithy_client.expectString
  });
  Object.assign(contents, doc);
  return contents;
}, "de_CreateTenantCommand");
var de_CreateTenantResourceAssociationCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  await (0, import_smithy_client.collectBody)(output.body, context);
  return contents;
}, "de_CreateTenantResourceAssociationCommand");
var de_DeleteConfigurationSetCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  await (0, import_smithy_client.collectBody)(output.body, context);
  return contents;
}, "de_DeleteConfigurationSetCommand");
var de_DeleteConfigurationSetEventDestinationCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  await (0, import_smithy_client.collectBody)(output.body, context);
  return contents;
}, "de_DeleteConfigurationSetEventDestinationCommand");
var de_DeleteContactCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  await (0, import_smithy_client.collectBody)(output.body, context);
  return contents;
}, "de_DeleteContactCommand");
var de_DeleteContactListCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  await (0, import_smithy_client.collectBody)(output.body, context);
  return contents;
}, "de_DeleteContactListCommand");
var de_DeleteCustomVerificationEmailTemplateCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  await (0, import_smithy_client.collectBody)(output.body, context);
  return contents;
}, "de_DeleteCustomVerificationEmailTemplateCommand");
var de_DeleteDedicatedIpPoolCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  await (0, import_smithy_client.collectBody)(output.body, context);
  return contents;
}, "de_DeleteDedicatedIpPoolCommand");
var de_DeleteEmailIdentityCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  await (0, import_smithy_client.collectBody)(output.body, context);
  return contents;
}, "de_DeleteEmailIdentityCommand");
var de_DeleteEmailIdentityPolicyCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  await (0, import_smithy_client.collectBody)(output.body, context);
  return contents;
}, "de_DeleteEmailIdentityPolicyCommand");
var de_DeleteEmailTemplateCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  await (0, import_smithy_client.collectBody)(output.body, context);
  return contents;
}, "de_DeleteEmailTemplateCommand");
var de_DeleteMultiRegionEndpointCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  const data = (0, import_smithy_client.expectNonNull)((0, import_smithy_client.expectObject)(await (0, import_core2.parseJsonBody)(output.body, context)), "body");
  const doc = (0, import_smithy_client.take)(data, {
    Status: import_smithy_client.expectString
  });
  Object.assign(contents, doc);
  return contents;
}, "de_DeleteMultiRegionEndpointCommand");
var de_DeleteSuppressedDestinationCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  await (0, import_smithy_client.collectBody)(output.body, context);
  return contents;
}, "de_DeleteSuppressedDestinationCommand");
var de_DeleteTenantCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  await (0, import_smithy_client.collectBody)(output.body, context);
  return contents;
}, "de_DeleteTenantCommand");
var de_DeleteTenantResourceAssociationCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  await (0, import_smithy_client.collectBody)(output.body, context);
  return contents;
}, "de_DeleteTenantResourceAssociationCommand");
var de_GetAccountCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  const data = (0, import_smithy_client.expectNonNull)((0, import_smithy_client.expectObject)(await (0, import_core2.parseJsonBody)(output.body, context)), "body");
  const doc = (0, import_smithy_client.take)(data, {
    DedicatedIpAutoWarmupEnabled: import_smithy_client.expectBoolean,
    Details: import_smithy_client._json,
    EnforcementStatus: import_smithy_client.expectString,
    ProductionAccessEnabled: import_smithy_client.expectBoolean,
    SendQuota: /* @__PURE__ */ __name((_) => de_SendQuota(_, context), "SendQuota"),
    SendingEnabled: import_smithy_client.expectBoolean,
    SuppressionAttributes: import_smithy_client._json,
    VdmAttributes: import_smithy_client._json
  });
  Object.assign(contents, doc);
  return contents;
}, "de_GetAccountCommand");
var de_GetBlacklistReportsCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  const data = (0, import_smithy_client.expectNonNull)((0, import_smithy_client.expectObject)(await (0, import_core2.parseJsonBody)(output.body, context)), "body");
  const doc = (0, import_smithy_client.take)(data, {
    BlacklistReport: /* @__PURE__ */ __name((_) => de_BlacklistReport(_, context), "BlacklistReport")
  });
  Object.assign(contents, doc);
  return contents;
}, "de_GetBlacklistReportsCommand");
var de_GetConfigurationSetCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  const data = (0, import_smithy_client.expectNonNull)((0, import_smithy_client.expectObject)(await (0, import_core2.parseJsonBody)(output.body, context)), "body");
  const doc = (0, import_smithy_client.take)(data, {
    ArchivingOptions: import_smithy_client._json,
    ConfigurationSetName: import_smithy_client.expectString,
    DeliveryOptions: import_smithy_client._json,
    ReputationOptions: /* @__PURE__ */ __name((_) => de_ReputationOptions(_, context), "ReputationOptions"),
    SendingOptions: import_smithy_client._json,
    SuppressionOptions: import_smithy_client._json,
    Tags: import_smithy_client._json,
    TrackingOptions: import_smithy_client._json,
    VdmOptions: import_smithy_client._json
  });
  Object.assign(contents, doc);
  return contents;
}, "de_GetConfigurationSetCommand");
var de_GetConfigurationSetEventDestinationsCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  const data = (0, import_smithy_client.expectNonNull)((0, import_smithy_client.expectObject)(await (0, import_core2.parseJsonBody)(output.body, context)), "body");
  const doc = (0, import_smithy_client.take)(data, {
    EventDestinations: import_smithy_client._json
  });
  Object.assign(contents, doc);
  return contents;
}, "de_GetConfigurationSetEventDestinationsCommand");
var de_GetContactCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  const data = (0, import_smithy_client.expectNonNull)((0, import_smithy_client.expectObject)(await (0, import_core2.parseJsonBody)(output.body, context)), "body");
  const doc = (0, import_smithy_client.take)(data, {
    AttributesData: import_smithy_client.expectString,
    ContactListName: import_smithy_client.expectString,
    CreatedTimestamp: /* @__PURE__ */ __name((_) => (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseEpochTimestamp)((0, import_smithy_client.expectNumber)(_))), "CreatedTimestamp"),
    EmailAddress: import_smithy_client.expectString,
    LastUpdatedTimestamp: /* @__PURE__ */ __name((_) => (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseEpochTimestamp)((0, import_smithy_client.expectNumber)(_))), "LastUpdatedTimestamp"),
    TopicDefaultPreferences: import_smithy_client._json,
    TopicPreferences: import_smithy_client._json,
    UnsubscribeAll: import_smithy_client.expectBoolean
  });
  Object.assign(contents, doc);
  return contents;
}, "de_GetContactCommand");
var de_GetContactListCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  const data = (0, import_smithy_client.expectNonNull)((0, import_smithy_client.expectObject)(await (0, import_core2.parseJsonBody)(output.body, context)), "body");
  const doc = (0, import_smithy_client.take)(data, {
    ContactListName: import_smithy_client.expectString,
    CreatedTimestamp: /* @__PURE__ */ __name((_) => (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseEpochTimestamp)((0, import_smithy_client.expectNumber)(_))), "CreatedTimestamp"),
    Description: import_smithy_client.expectString,
    LastUpdatedTimestamp: /* @__PURE__ */ __name((_) => (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseEpochTimestamp)((0, import_smithy_client.expectNumber)(_))), "LastUpdatedTimestamp"),
    Tags: import_smithy_client._json,
    Topics: import_smithy_client._json
  });
  Object.assign(contents, doc);
  return contents;
}, "de_GetContactListCommand");
var de_GetCustomVerificationEmailTemplateCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  const data = (0, import_smithy_client.expectNonNull)((0, import_smithy_client.expectObject)(await (0, import_core2.parseJsonBody)(output.body, context)), "body");
  const doc = (0, import_smithy_client.take)(data, {
    FailureRedirectionURL: import_smithy_client.expectString,
    FromEmailAddress: import_smithy_client.expectString,
    SuccessRedirectionURL: import_smithy_client.expectString,
    TemplateContent: import_smithy_client.expectString,
    TemplateName: import_smithy_client.expectString,
    TemplateSubject: import_smithy_client.expectString
  });
  Object.assign(contents, doc);
  return contents;
}, "de_GetCustomVerificationEmailTemplateCommand");
var de_GetDedicatedIpCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  const data = (0, import_smithy_client.expectNonNull)((0, import_smithy_client.expectObject)(await (0, import_core2.parseJsonBody)(output.body, context)), "body");
  const doc = (0, import_smithy_client.take)(data, {
    DedicatedIp: import_smithy_client._json
  });
  Object.assign(contents, doc);
  return contents;
}, "de_GetDedicatedIpCommand");
var de_GetDedicatedIpPoolCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  const data = (0, import_smithy_client.expectNonNull)((0, import_smithy_client.expectObject)(await (0, import_core2.parseJsonBody)(output.body, context)), "body");
  const doc = (0, import_smithy_client.take)(data, {
    DedicatedIpPool: import_smithy_client._json
  });
  Object.assign(contents, doc);
  return contents;
}, "de_GetDedicatedIpPoolCommand");
var de_GetDedicatedIpsCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  const data = (0, import_smithy_client.expectNonNull)((0, import_smithy_client.expectObject)(await (0, import_core2.parseJsonBody)(output.body, context)), "body");
  const doc = (0, import_smithy_client.take)(data, {
    DedicatedIps: import_smithy_client._json,
    NextToken: import_smithy_client.expectString
  });
  Object.assign(contents, doc);
  return contents;
}, "de_GetDedicatedIpsCommand");
var de_GetDeliverabilityDashboardOptionsCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  const data = (0, import_smithy_client.expectNonNull)((0, import_smithy_client.expectObject)(await (0, import_core2.parseJsonBody)(output.body, context)), "body");
  const doc = (0, import_smithy_client.take)(data, {
    AccountStatus: import_smithy_client.expectString,
    ActiveSubscribedDomains: /* @__PURE__ */ __name((_) => de_DomainDeliverabilityTrackingOptions(_, context), "ActiveSubscribedDomains"),
    DashboardEnabled: import_smithy_client.expectBoolean,
    PendingExpirationSubscribedDomains: /* @__PURE__ */ __name((_) => de_DomainDeliverabilityTrackingOptions(_, context), "PendingExpirationSubscribedDomains"),
    SubscriptionExpiryDate: /* @__PURE__ */ __name((_) => (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseEpochTimestamp)((0, import_smithy_client.expectNumber)(_))), "SubscriptionExpiryDate")
  });
  Object.assign(contents, doc);
  return contents;
}, "de_GetDeliverabilityDashboardOptionsCommand");
var de_GetDeliverabilityTestReportCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  const data = (0, import_smithy_client.expectNonNull)((0, import_smithy_client.expectObject)(await (0, import_core2.parseJsonBody)(output.body, context)), "body");
  const doc = (0, import_smithy_client.take)(data, {
    DeliverabilityTestReport: /* @__PURE__ */ __name((_) => de_DeliverabilityTestReport(_, context), "DeliverabilityTestReport"),
    IspPlacements: /* @__PURE__ */ __name((_) => de_IspPlacements(_, context), "IspPlacements"),
    Message: import_smithy_client.expectString,
    OverallPlacement: /* @__PURE__ */ __name((_) => de_PlacementStatistics(_, context), "OverallPlacement"),
    Tags: import_smithy_client._json
  });
  Object.assign(contents, doc);
  return contents;
}, "de_GetDeliverabilityTestReportCommand");
var de_GetDomainDeliverabilityCampaignCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  const data = (0, import_smithy_client.expectNonNull)((0, import_smithy_client.expectObject)(await (0, import_core2.parseJsonBody)(output.body, context)), "body");
  const doc = (0, import_smithy_client.take)(data, {
    DomainDeliverabilityCampaign: /* @__PURE__ */ __name((_) => de_DomainDeliverabilityCampaign(_, context), "DomainDeliverabilityCampaign")
  });
  Object.assign(contents, doc);
  return contents;
}, "de_GetDomainDeliverabilityCampaignCommand");
var de_GetDomainStatisticsReportCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  const data = (0, import_smithy_client.expectNonNull)((0, import_smithy_client.expectObject)(await (0, import_core2.parseJsonBody)(output.body, context)), "body");
  const doc = (0, import_smithy_client.take)(data, {
    DailyVolumes: /* @__PURE__ */ __name((_) => de_DailyVolumes(_, context), "DailyVolumes"),
    OverallVolume: /* @__PURE__ */ __name((_) => de_OverallVolume(_, context), "OverallVolume")
  });
  Object.assign(contents, doc);
  return contents;
}, "de_GetDomainStatisticsReportCommand");
var de_GetEmailIdentityCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  const data = (0, import_smithy_client.expectNonNull)((0, import_smithy_client.expectObject)(await (0, import_core2.parseJsonBody)(output.body, context)), "body");
  const doc = (0, import_smithy_client.take)(data, {
    ConfigurationSetName: import_smithy_client.expectString,
    DkimAttributes: /* @__PURE__ */ __name((_) => de_DkimAttributes(_, context), "DkimAttributes"),
    FeedbackForwardingStatus: import_smithy_client.expectBoolean,
    IdentityType: import_smithy_client.expectString,
    MailFromAttributes: import_smithy_client._json,
    Policies: import_smithy_client._json,
    Tags: import_smithy_client._json,
    VerificationInfo: /* @__PURE__ */ __name((_) => de_VerificationInfo(_, context), "VerificationInfo"),
    VerificationStatus: import_smithy_client.expectString,
    VerifiedForSendingStatus: import_smithy_client.expectBoolean
  });
  Object.assign(contents, doc);
  return contents;
}, "de_GetEmailIdentityCommand");
var de_GetEmailIdentityPoliciesCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  const data = (0, import_smithy_client.expectNonNull)((0, import_smithy_client.expectObject)(await (0, import_core2.parseJsonBody)(output.body, context)), "body");
  const doc = (0, import_smithy_client.take)(data, {
    Policies: import_smithy_client._json
  });
  Object.assign(contents, doc);
  return contents;
}, "de_GetEmailIdentityPoliciesCommand");
var de_GetEmailTemplateCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  const data = (0, import_smithy_client.expectNonNull)((0, import_smithy_client.expectObject)(await (0, import_core2.parseJsonBody)(output.body, context)), "body");
  const doc = (0, import_smithy_client.take)(data, {
    TemplateContent: import_smithy_client._json,
    TemplateName: import_smithy_client.expectString
  });
  Object.assign(contents, doc);
  return contents;
}, "de_GetEmailTemplateCommand");
var de_GetExportJobCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  const data = (0, import_smithy_client.expectNonNull)((0, import_smithy_client.expectObject)(await (0, import_core2.parseJsonBody)(output.body, context)), "body");
  const doc = (0, import_smithy_client.take)(data, {
    CompletedTimestamp: /* @__PURE__ */ __name((_) => (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseEpochTimestamp)((0, import_smithy_client.expectNumber)(_))), "CompletedTimestamp"),
    CreatedTimestamp: /* @__PURE__ */ __name((_) => (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseEpochTimestamp)((0, import_smithy_client.expectNumber)(_))), "CreatedTimestamp"),
    ExportDataSource: /* @__PURE__ */ __name((_) => de_ExportDataSource(_, context), "ExportDataSource"),
    ExportDestination: import_smithy_client._json,
    ExportSourceType: import_smithy_client.expectString,
    FailureInfo: import_smithy_client._json,
    JobId: import_smithy_client.expectString,
    JobStatus: import_smithy_client.expectString,
    Statistics: import_smithy_client._json
  });
  Object.assign(contents, doc);
  return contents;
}, "de_GetExportJobCommand");
var de_GetImportJobCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  const data = (0, import_smithy_client.expectNonNull)((0, import_smithy_client.expectObject)(await (0, import_core2.parseJsonBody)(output.body, context)), "body");
  const doc = (0, import_smithy_client.take)(data, {
    CompletedTimestamp: /* @__PURE__ */ __name((_) => (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseEpochTimestamp)((0, import_smithy_client.expectNumber)(_))), "CompletedTimestamp"),
    CreatedTimestamp: /* @__PURE__ */ __name((_) => (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseEpochTimestamp)((0, import_smithy_client.expectNumber)(_))), "CreatedTimestamp"),
    FailedRecordsCount: import_smithy_client.expectInt32,
    FailureInfo: import_smithy_client._json,
    ImportDataSource: import_smithy_client._json,
    ImportDestination: import_smithy_client._json,
    JobId: import_smithy_client.expectString,
    JobStatus: import_smithy_client.expectString,
    ProcessedRecordsCount: import_smithy_client.expectInt32
  });
  Object.assign(contents, doc);
  return contents;
}, "de_GetImportJobCommand");
var de_GetMessageInsightsCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  const data = (0, import_smithy_client.expectNonNull)((0, import_smithy_client.expectObject)(await (0, import_core2.parseJsonBody)(output.body, context)), "body");
  const doc = (0, import_smithy_client.take)(data, {
    EmailTags: import_smithy_client._json,
    FromEmailAddress: import_smithy_client.expectString,
    Insights: /* @__PURE__ */ __name((_) => de_EmailInsightsList(_, context), "Insights"),
    MessageId: import_smithy_client.expectString,
    Subject: import_smithy_client.expectString
  });
  Object.assign(contents, doc);
  return contents;
}, "de_GetMessageInsightsCommand");
var de_GetMultiRegionEndpointCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  const data = (0, import_smithy_client.expectNonNull)((0, import_smithy_client.expectObject)(await (0, import_core2.parseJsonBody)(output.body, context)), "body");
  const doc = (0, import_smithy_client.take)(data, {
    CreatedTimestamp: /* @__PURE__ */ __name((_) => (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseEpochTimestamp)((0, import_smithy_client.expectNumber)(_))), "CreatedTimestamp"),
    EndpointId: import_smithy_client.expectString,
    EndpointName: import_smithy_client.expectString,
    LastUpdatedTimestamp: /* @__PURE__ */ __name((_) => (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseEpochTimestamp)((0, import_smithy_client.expectNumber)(_))), "LastUpdatedTimestamp"),
    Routes: import_smithy_client._json,
    Status: import_smithy_client.expectString
  });
  Object.assign(contents, doc);
  return contents;
}, "de_GetMultiRegionEndpointCommand");
var de_GetReputationEntityCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  const data = (0, import_smithy_client.expectNonNull)((0, import_smithy_client.expectObject)(await (0, import_core2.parseJsonBody)(output.body, context)), "body");
  const doc = (0, import_smithy_client.take)(data, {
    ReputationEntity: /* @__PURE__ */ __name((_) => de_ReputationEntity(_, context), "ReputationEntity")
  });
  Object.assign(contents, doc);
  return contents;
}, "de_GetReputationEntityCommand");
var de_GetSuppressedDestinationCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  const data = (0, import_smithy_client.expectNonNull)((0, import_smithy_client.expectObject)(await (0, import_core2.parseJsonBody)(output.body, context)), "body");
  const doc = (0, import_smithy_client.take)(data, {
    SuppressedDestination: /* @__PURE__ */ __name((_) => de_SuppressedDestination(_, context), "SuppressedDestination")
  });
  Object.assign(contents, doc);
  return contents;
}, "de_GetSuppressedDestinationCommand");
var de_GetTenantCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  const data = (0, import_smithy_client.expectNonNull)((0, import_smithy_client.expectObject)(await (0, import_core2.parseJsonBody)(output.body, context)), "body");
  const doc = (0, import_smithy_client.take)(data, {
    Tenant: /* @__PURE__ */ __name((_) => de_Tenant(_, context), "Tenant")
  });
  Object.assign(contents, doc);
  return contents;
}, "de_GetTenantCommand");
var de_ListConfigurationSetsCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  const data = (0, import_smithy_client.expectNonNull)((0, import_smithy_client.expectObject)(await (0, import_core2.parseJsonBody)(output.body, context)), "body");
  const doc = (0, import_smithy_client.take)(data, {
    ConfigurationSets: import_smithy_client._json,
    NextToken: import_smithy_client.expectString
  });
  Object.assign(contents, doc);
  return contents;
}, "de_ListConfigurationSetsCommand");
var de_ListContactListsCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  const data = (0, import_smithy_client.expectNonNull)((0, import_smithy_client.expectObject)(await (0, import_core2.parseJsonBody)(output.body, context)), "body");
  const doc = (0, import_smithy_client.take)(data, {
    ContactLists: /* @__PURE__ */ __name((_) => de_ListOfContactLists(_, context), "ContactLists"),
    NextToken: import_smithy_client.expectString
  });
  Object.assign(contents, doc);
  return contents;
}, "de_ListContactListsCommand");
var de_ListContactsCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  const data = (0, import_smithy_client.expectNonNull)((0, import_smithy_client.expectObject)(await (0, import_core2.parseJsonBody)(output.body, context)), "body");
  const doc = (0, import_smithy_client.take)(data, {
    Contacts: /* @__PURE__ */ __name((_) => de_ListOfContacts(_, context), "Contacts"),
    NextToken: import_smithy_client.expectString
  });
  Object.assign(contents, doc);
  return contents;
}, "de_ListContactsCommand");
var de_ListCustomVerificationEmailTemplatesCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  const data = (0, import_smithy_client.expectNonNull)((0, import_smithy_client.expectObject)(await (0, import_core2.parseJsonBody)(output.body, context)), "body");
  const doc = (0, import_smithy_client.take)(data, {
    CustomVerificationEmailTemplates: import_smithy_client._json,
    NextToken: import_smithy_client.expectString
  });
  Object.assign(contents, doc);
  return contents;
}, "de_ListCustomVerificationEmailTemplatesCommand");
var de_ListDedicatedIpPoolsCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  const data = (0, import_smithy_client.expectNonNull)((0, import_smithy_client.expectObject)(await (0, import_core2.parseJsonBody)(output.body, context)), "body");
  const doc = (0, import_smithy_client.take)(data, {
    DedicatedIpPools: import_smithy_client._json,
    NextToken: import_smithy_client.expectString
  });
  Object.assign(contents, doc);
  return contents;
}, "de_ListDedicatedIpPoolsCommand");
var de_ListDeliverabilityTestReportsCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  const data = (0, import_smithy_client.expectNonNull)((0, import_smithy_client.expectObject)(await (0, import_core2.parseJsonBody)(output.body, context)), "body");
  const doc = (0, import_smithy_client.take)(data, {
    DeliverabilityTestReports: /* @__PURE__ */ __name((_) => de_DeliverabilityTestReports(_, context), "DeliverabilityTestReports"),
    NextToken: import_smithy_client.expectString
  });
  Object.assign(contents, doc);
  return contents;
}, "de_ListDeliverabilityTestReportsCommand");
var de_ListDomainDeliverabilityCampaignsCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  const data = (0, import_smithy_client.expectNonNull)((0, import_smithy_client.expectObject)(await (0, import_core2.parseJsonBody)(output.body, context)), "body");
  const doc = (0, import_smithy_client.take)(data, {
    DomainDeliverabilityCampaigns: /* @__PURE__ */ __name((_) => de_DomainDeliverabilityCampaignList(_, context), "DomainDeliverabilityCampaigns"),
    NextToken: import_smithy_client.expectString
  });
  Object.assign(contents, doc);
  return contents;
}, "de_ListDomainDeliverabilityCampaignsCommand");
var de_ListEmailIdentitiesCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  const data = (0, import_smithy_client.expectNonNull)((0, import_smithy_client.expectObject)(await (0, import_core2.parseJsonBody)(output.body, context)), "body");
  const doc = (0, import_smithy_client.take)(data, {
    EmailIdentities: import_smithy_client._json,
    NextToken: import_smithy_client.expectString
  });
  Object.assign(contents, doc);
  return contents;
}, "de_ListEmailIdentitiesCommand");
var de_ListEmailTemplatesCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  const data = (0, import_smithy_client.expectNonNull)((0, import_smithy_client.expectObject)(await (0, import_core2.parseJsonBody)(output.body, context)), "body");
  const doc = (0, import_smithy_client.take)(data, {
    NextToken: import_smithy_client.expectString,
    TemplatesMetadata: /* @__PURE__ */ __name((_) => de_EmailTemplateMetadataList(_, context), "TemplatesMetadata")
  });
  Object.assign(contents, doc);
  return contents;
}, "de_ListEmailTemplatesCommand");
var de_ListExportJobsCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  const data = (0, import_smithy_client.expectNonNull)((0, import_smithy_client.expectObject)(await (0, import_core2.parseJsonBody)(output.body, context)), "body");
  const doc = (0, import_smithy_client.take)(data, {
    ExportJobs: /* @__PURE__ */ __name((_) => de_ExportJobSummaryList(_, context), "ExportJobs"),
    NextToken: import_smithy_client.expectString
  });
  Object.assign(contents, doc);
  return contents;
}, "de_ListExportJobsCommand");
var de_ListImportJobsCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  const data = (0, import_smithy_client.expectNonNull)((0, import_smithy_client.expectObject)(await (0, import_core2.parseJsonBody)(output.body, context)), "body");
  const doc = (0, import_smithy_client.take)(data, {
    ImportJobs: /* @__PURE__ */ __name((_) => de_ImportJobSummaryList(_, context), "ImportJobs"),
    NextToken: import_smithy_client.expectString
  });
  Object.assign(contents, doc);
  return contents;
}, "de_ListImportJobsCommand");
var de_ListMultiRegionEndpointsCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  const data = (0, import_smithy_client.expectNonNull)((0, import_smithy_client.expectObject)(await (0, import_core2.parseJsonBody)(output.body, context)), "body");
  const doc = (0, import_smithy_client.take)(data, {
    MultiRegionEndpoints: /* @__PURE__ */ __name((_) => de_MultiRegionEndpoints(_, context), "MultiRegionEndpoints"),
    NextToken: import_smithy_client.expectString
  });
  Object.assign(contents, doc);
  return contents;
}, "de_ListMultiRegionEndpointsCommand");
var de_ListRecommendationsCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  const data = (0, import_smithy_client.expectNonNull)((0, import_smithy_client.expectObject)(await (0, import_core2.parseJsonBody)(output.body, context)), "body");
  const doc = (0, import_smithy_client.take)(data, {
    NextToken: import_smithy_client.expectString,
    Recommendations: /* @__PURE__ */ __name((_) => de_RecommendationsList(_, context), "Recommendations")
  });
  Object.assign(contents, doc);
  return contents;
}, "de_ListRecommendationsCommand");
var de_ListReputationEntitiesCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  const data = (0, import_smithy_client.expectNonNull)((0, import_smithy_client.expectObject)(await (0, import_core2.parseJsonBody)(output.body, context)), "body");
  const doc = (0, import_smithy_client.take)(data, {
    NextToken: import_smithy_client.expectString,
    ReputationEntities: /* @__PURE__ */ __name((_) => de_ReputationEntitiesList(_, context), "ReputationEntities")
  });
  Object.assign(contents, doc);
  return contents;
}, "de_ListReputationEntitiesCommand");
var de_ListResourceTenantsCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  const data = (0, import_smithy_client.expectNonNull)((0, import_smithy_client.expectObject)(await (0, import_core2.parseJsonBody)(output.body, context)), "body");
  const doc = (0, import_smithy_client.take)(data, {
    NextToken: import_smithy_client.expectString,
    ResourceTenants: /* @__PURE__ */ __name((_) => de_ResourceTenantMetadataList(_, context), "ResourceTenants")
  });
  Object.assign(contents, doc);
  return contents;
}, "de_ListResourceTenantsCommand");
var de_ListSuppressedDestinationsCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  const data = (0, import_smithy_client.expectNonNull)((0, import_smithy_client.expectObject)(await (0, import_core2.parseJsonBody)(output.body, context)), "body");
  const doc = (0, import_smithy_client.take)(data, {
    NextToken: import_smithy_client.expectString,
    SuppressedDestinationSummaries: /* @__PURE__ */ __name((_) => de_SuppressedDestinationSummaries(_, context), "SuppressedDestinationSummaries")
  });
  Object.assign(contents, doc);
  return contents;
}, "de_ListSuppressedDestinationsCommand");
var de_ListTagsForResourceCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  const data = (0, import_smithy_client.expectNonNull)((0, import_smithy_client.expectObject)(await (0, import_core2.parseJsonBody)(output.body, context)), "body");
  const doc = (0, import_smithy_client.take)(data, {
    Tags: import_smithy_client._json
  });
  Object.assign(contents, doc);
  return contents;
}, "de_ListTagsForResourceCommand");
var de_ListTenantResourcesCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  const data = (0, import_smithy_client.expectNonNull)((0, import_smithy_client.expectObject)(await (0, import_core2.parseJsonBody)(output.body, context)), "body");
  const doc = (0, import_smithy_client.take)(data, {
    NextToken: import_smithy_client.expectString,
    TenantResources: import_smithy_client._json
  });
  Object.assign(contents, doc);
  return contents;
}, "de_ListTenantResourcesCommand");
var de_ListTenantsCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  const data = (0, import_smithy_client.expectNonNull)((0, import_smithy_client.expectObject)(await (0, import_core2.parseJsonBody)(output.body, context)), "body");
  const doc = (0, import_smithy_client.take)(data, {
    NextToken: import_smithy_client.expectString,
    Tenants: /* @__PURE__ */ __name((_) => de_TenantInfoList(_, context), "Tenants")
  });
  Object.assign(contents, doc);
  return contents;
}, "de_ListTenantsCommand");
var de_PutAccountDedicatedIpWarmupAttributesCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  await (0, import_smithy_client.collectBody)(output.body, context);
  return contents;
}, "de_PutAccountDedicatedIpWarmupAttributesCommand");
var de_PutAccountDetailsCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  await (0, import_smithy_client.collectBody)(output.body, context);
  return contents;
}, "de_PutAccountDetailsCommand");
var de_PutAccountSendingAttributesCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  await (0, import_smithy_client.collectBody)(output.body, context);
  return contents;
}, "de_PutAccountSendingAttributesCommand");
var de_PutAccountSuppressionAttributesCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  await (0, import_smithy_client.collectBody)(output.body, context);
  return contents;
}, "de_PutAccountSuppressionAttributesCommand");
var de_PutAccountVdmAttributesCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  await (0, import_smithy_client.collectBody)(output.body, context);
  return contents;
}, "de_PutAccountVdmAttributesCommand");
var de_PutConfigurationSetArchivingOptionsCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  await (0, import_smithy_client.collectBody)(output.body, context);
  return contents;
}, "de_PutConfigurationSetArchivingOptionsCommand");
var de_PutConfigurationSetDeliveryOptionsCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  await (0, import_smithy_client.collectBody)(output.body, context);
  return contents;
}, "de_PutConfigurationSetDeliveryOptionsCommand");
var de_PutConfigurationSetReputationOptionsCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  await (0, import_smithy_client.collectBody)(output.body, context);
  return contents;
}, "de_PutConfigurationSetReputationOptionsCommand");
var de_PutConfigurationSetSendingOptionsCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  await (0, import_smithy_client.collectBody)(output.body, context);
  return contents;
}, "de_PutConfigurationSetSendingOptionsCommand");
var de_PutConfigurationSetSuppressionOptionsCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  await (0, import_smithy_client.collectBody)(output.body, context);
  return contents;
}, "de_PutConfigurationSetSuppressionOptionsCommand");
var de_PutConfigurationSetTrackingOptionsCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  await (0, import_smithy_client.collectBody)(output.body, context);
  return contents;
}, "de_PutConfigurationSetTrackingOptionsCommand");
var de_PutConfigurationSetVdmOptionsCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  await (0, import_smithy_client.collectBody)(output.body, context);
  return contents;
}, "de_PutConfigurationSetVdmOptionsCommand");
var de_PutDedicatedIpInPoolCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  await (0, import_smithy_client.collectBody)(output.body, context);
  return contents;
}, "de_PutDedicatedIpInPoolCommand");
var de_PutDedicatedIpPoolScalingAttributesCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  await (0, import_smithy_client.collectBody)(output.body, context);
  return contents;
}, "de_PutDedicatedIpPoolScalingAttributesCommand");
var de_PutDedicatedIpWarmupAttributesCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  await (0, import_smithy_client.collectBody)(output.body, context);
  return contents;
}, "de_PutDedicatedIpWarmupAttributesCommand");
var de_PutDeliverabilityDashboardOptionCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  await (0, import_smithy_client.collectBody)(output.body, context);
  return contents;
}, "de_PutDeliverabilityDashboardOptionCommand");
var de_PutEmailIdentityConfigurationSetAttributesCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  await (0, import_smithy_client.collectBody)(output.body, context);
  return contents;
}, "de_PutEmailIdentityConfigurationSetAttributesCommand");
var de_PutEmailIdentityDkimAttributesCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  await (0, import_smithy_client.collectBody)(output.body, context);
  return contents;
}, "de_PutEmailIdentityDkimAttributesCommand");
var de_PutEmailIdentityDkimSigningAttributesCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  const data = (0, import_smithy_client.expectNonNull)((0, import_smithy_client.expectObject)(await (0, import_core2.parseJsonBody)(output.body, context)), "body");
  const doc = (0, import_smithy_client.take)(data, {
    DkimStatus: import_smithy_client.expectString,
    DkimTokens: import_smithy_client._json
  });
  Object.assign(contents, doc);
  return contents;
}, "de_PutEmailIdentityDkimSigningAttributesCommand");
var de_PutEmailIdentityFeedbackAttributesCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  await (0, import_smithy_client.collectBody)(output.body, context);
  return contents;
}, "de_PutEmailIdentityFeedbackAttributesCommand");
var de_PutEmailIdentityMailFromAttributesCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  await (0, import_smithy_client.collectBody)(output.body, context);
  return contents;
}, "de_PutEmailIdentityMailFromAttributesCommand");
var de_PutSuppressedDestinationCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  await (0, import_smithy_client.collectBody)(output.body, context);
  return contents;
}, "de_PutSuppressedDestinationCommand");
var de_SendBulkEmailCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  const data = (0, import_smithy_client.expectNonNull)((0, import_smithy_client.expectObject)(await (0, import_core2.parseJsonBody)(output.body, context)), "body");
  const doc = (0, import_smithy_client.take)(data, {
    BulkEmailEntryResults: import_smithy_client._json
  });
  Object.assign(contents, doc);
  return contents;
}, "de_SendBulkEmailCommand");
var de_SendCustomVerificationEmailCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  const data = (0, import_smithy_client.expectNonNull)((0, import_smithy_client.expectObject)(await (0, import_core2.parseJsonBody)(output.body, context)), "body");
  const doc = (0, import_smithy_client.take)(data, {
    MessageId: import_smithy_client.expectString
  });
  Object.assign(contents, doc);
  return contents;
}, "de_SendCustomVerificationEmailCommand");
var de_SendEmailCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  const data = (0, import_smithy_client.expectNonNull)((0, import_smithy_client.expectObject)(await (0, import_core2.parseJsonBody)(output.body, context)), "body");
  const doc = (0, import_smithy_client.take)(data, {
    MessageId: import_smithy_client.expectString
  });
  Object.assign(contents, doc);
  return contents;
}, "de_SendEmailCommand");
var de_TagResourceCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  await (0, import_smithy_client.collectBody)(output.body, context);
  return contents;
}, "de_TagResourceCommand");
var de_TestRenderEmailTemplateCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  const data = (0, import_smithy_client.expectNonNull)((0, import_smithy_client.expectObject)(await (0, import_core2.parseJsonBody)(output.body, context)), "body");
  const doc = (0, import_smithy_client.take)(data, {
    RenderedTemplate: import_smithy_client.expectString
  });
  Object.assign(contents, doc);
  return contents;
}, "de_TestRenderEmailTemplateCommand");
var de_UntagResourceCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  await (0, import_smithy_client.collectBody)(output.body, context);
  return contents;
}, "de_UntagResourceCommand");
var de_UpdateConfigurationSetEventDestinationCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  await (0, import_smithy_client.collectBody)(output.body, context);
  return contents;
}, "de_UpdateConfigurationSetEventDestinationCommand");
var de_UpdateContactCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  await (0, import_smithy_client.collectBody)(output.body, context);
  return contents;
}, "de_UpdateContactCommand");
var de_UpdateContactListCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  await (0, import_smithy_client.collectBody)(output.body, context);
  return contents;
}, "de_UpdateContactListCommand");
var de_UpdateCustomVerificationEmailTemplateCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  await (0, import_smithy_client.collectBody)(output.body, context);
  return contents;
}, "de_UpdateCustomVerificationEmailTemplateCommand");
var de_UpdateEmailIdentityPolicyCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  await (0, import_smithy_client.collectBody)(output.body, context);
  return contents;
}, "de_UpdateEmailIdentityPolicyCommand");
var de_UpdateEmailTemplateCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  await (0, import_smithy_client.collectBody)(output.body, context);
  return contents;
}, "de_UpdateEmailTemplateCommand");
var de_UpdateReputationEntityCustomerManagedStatusCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  await (0, import_smithy_client.collectBody)(output.body, context);
  return contents;
}, "de_UpdateReputationEntityCustomerManagedStatusCommand");
var de_UpdateReputationEntityPolicyCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  await (0, import_smithy_client.collectBody)(output.body, context);
  return contents;
}, "de_UpdateReputationEntityPolicyCommand");
var de_CommandError = /* @__PURE__ */ __name(async (output, context) => {
  const parsedOutput = {
    ...output,
    body: await (0, import_core2.parseJsonErrorBody)(output.body, context)
  };
  const errorCode = (0, import_core2.loadRestJsonErrorCode)(output, parsedOutput.body);
  switch (errorCode) {
    case "BadRequestException":
    case "com.amazonaws.sesv2#BadRequestException":
      throw await de_BadRequestExceptionRes(parsedOutput, context);
    case "InternalServiceErrorException":
    case "com.amazonaws.sesv2#InternalServiceErrorException":
      throw await de_InternalServiceErrorExceptionRes(parsedOutput, context);
    case "NotFoundException":
    case "com.amazonaws.sesv2#NotFoundException":
      throw await de_NotFoundExceptionRes(parsedOutput, context);
    case "TooManyRequestsException":
    case "com.amazonaws.sesv2#TooManyRequestsException":
      throw await de_TooManyRequestsExceptionRes(parsedOutput, context);
    case "AlreadyExistsException":
    case "com.amazonaws.sesv2#AlreadyExistsException":
      throw await de_AlreadyExistsExceptionRes(parsedOutput, context);
    case "ConcurrentModificationException":
    case "com.amazonaws.sesv2#ConcurrentModificationException":
      throw await de_ConcurrentModificationExceptionRes(parsedOutput, context);
    case "LimitExceededException":
    case "com.amazonaws.sesv2#LimitExceededException":
      throw await de_LimitExceededExceptionRes(parsedOutput, context);
    case "AccountSuspendedException":
    case "com.amazonaws.sesv2#AccountSuspendedException":
      throw await de_AccountSuspendedExceptionRes(parsedOutput, context);
    case "MailFromDomainNotVerifiedException":
    case "com.amazonaws.sesv2#MailFromDomainNotVerifiedException":
      throw await de_MailFromDomainNotVerifiedExceptionRes(parsedOutput, context);
    case "MessageRejected":
    case "com.amazonaws.sesv2#MessageRejected":
      throw await de_MessageRejectedRes(parsedOutput, context);
    case "SendingPausedException":
    case "com.amazonaws.sesv2#SendingPausedException":
      throw await de_SendingPausedExceptionRes(parsedOutput, context);
    case "InvalidNextTokenException":
    case "com.amazonaws.sesv2#InvalidNextTokenException":
      throw await de_InvalidNextTokenExceptionRes(parsedOutput, context);
    case "ConflictException":
    case "com.amazonaws.sesv2#ConflictException":
      throw await de_ConflictExceptionRes(parsedOutput, context);
    default:
      const parsedBody = parsedOutput.body;
      return throwDefaultError({
        output,
        parsedBody,
        errorCode
      });
  }
}, "de_CommandError");
var throwDefaultError = (0, import_smithy_client.withBaseException)(SESv2ServiceException);
var de_AccountSuspendedExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const contents = (0, import_smithy_client.map)({});
  const data = parsedOutput.body;
  const doc = (0, import_smithy_client.take)(data, {
    message: import_smithy_client.expectString
  });
  Object.assign(contents, doc);
  const exception = new AccountSuspendedException({
    $metadata: deserializeMetadata(parsedOutput),
    ...contents
  });
  return (0, import_smithy_client.decorateServiceException)(exception, parsedOutput.body);
}, "de_AccountSuspendedExceptionRes");
var de_AlreadyExistsExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const contents = (0, import_smithy_client.map)({});
  const data = parsedOutput.body;
  const doc = (0, import_smithy_client.take)(data, {
    message: import_smithy_client.expectString
  });
  Object.assign(contents, doc);
  const exception = new AlreadyExistsException({
    $metadata: deserializeMetadata(parsedOutput),
    ...contents
  });
  return (0, import_smithy_client.decorateServiceException)(exception, parsedOutput.body);
}, "de_AlreadyExistsExceptionRes");
var de_BadRequestExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const contents = (0, import_smithy_client.map)({});
  const data = parsedOutput.body;
  const doc = (0, import_smithy_client.take)(data, {
    message: import_smithy_client.expectString
  });
  Object.assign(contents, doc);
  const exception = new BadRequestException({
    $metadata: deserializeMetadata(parsedOutput),
    ...contents
  });
  return (0, import_smithy_client.decorateServiceException)(exception, parsedOutput.body);
}, "de_BadRequestExceptionRes");
var de_ConcurrentModificationExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const contents = (0, import_smithy_client.map)({});
  const data = parsedOutput.body;
  const doc = (0, import_smithy_client.take)(data, {
    message: import_smithy_client.expectString
  });
  Object.assign(contents, doc);
  const exception = new ConcurrentModificationException({
    $metadata: deserializeMetadata(parsedOutput),
    ...contents
  });
  return (0, import_smithy_client.decorateServiceException)(exception, parsedOutput.body);
}, "de_ConcurrentModificationExceptionRes");
var de_ConflictExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const contents = (0, import_smithy_client.map)({});
  const data = parsedOutput.body;
  const doc = (0, import_smithy_client.take)(data, {
    message: import_smithy_client.expectString
  });
  Object.assign(contents, doc);
  const exception = new ConflictException({
    $metadata: deserializeMetadata(parsedOutput),
    ...contents
  });
  return (0, import_smithy_client.decorateServiceException)(exception, parsedOutput.body);
}, "de_ConflictExceptionRes");
var de_InternalServiceErrorExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const contents = (0, import_smithy_client.map)({});
  const data = parsedOutput.body;
  const doc = (0, import_smithy_client.take)(data, {
    message: import_smithy_client.expectString
  });
  Object.assign(contents, doc);
  const exception = new InternalServiceErrorException({
    $metadata: deserializeMetadata(parsedOutput),
    ...contents
  });
  return (0, import_smithy_client.decorateServiceException)(exception, parsedOutput.body);
}, "de_InternalServiceErrorExceptionRes");
var de_InvalidNextTokenExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const contents = (0, import_smithy_client.map)({});
  const data = parsedOutput.body;
  const doc = (0, import_smithy_client.take)(data, {
    message: import_smithy_client.expectString
  });
  Object.assign(contents, doc);
  const exception = new InvalidNextTokenException({
    $metadata: deserializeMetadata(parsedOutput),
    ...contents
  });
  return (0, import_smithy_client.decorateServiceException)(exception, parsedOutput.body);
}, "de_InvalidNextTokenExceptionRes");
var de_LimitExceededExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const contents = (0, import_smithy_client.map)({});
  const data = parsedOutput.body;
  const doc = (0, import_smithy_client.take)(data, {
    message: import_smithy_client.expectString
  });
  Object.assign(contents, doc);
  const exception = new LimitExceededException({
    $metadata: deserializeMetadata(parsedOutput),
    ...contents
  });
  return (0, import_smithy_client.decorateServiceException)(exception, parsedOutput.body);
}, "de_LimitExceededExceptionRes");
var de_MailFromDomainNotVerifiedExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const contents = (0, import_smithy_client.map)({});
  const data = parsedOutput.body;
  const doc = (0, import_smithy_client.take)(data, {
    message: import_smithy_client.expectString
  });
  Object.assign(contents, doc);
  const exception = new MailFromDomainNotVerifiedException({
    $metadata: deserializeMetadata(parsedOutput),
    ...contents
  });
  return (0, import_smithy_client.decorateServiceException)(exception, parsedOutput.body);
}, "de_MailFromDomainNotVerifiedExceptionRes");
var de_MessageRejectedRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const contents = (0, import_smithy_client.map)({});
  const data = parsedOutput.body;
  const doc = (0, import_smithy_client.take)(data, {
    message: import_smithy_client.expectString
  });
  Object.assign(contents, doc);
  const exception = new MessageRejected({
    $metadata: deserializeMetadata(parsedOutput),
    ...contents
  });
  return (0, import_smithy_client.decorateServiceException)(exception, parsedOutput.body);
}, "de_MessageRejectedRes");
var de_NotFoundExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const contents = (0, import_smithy_client.map)({});
  const data = parsedOutput.body;
  const doc = (0, import_smithy_client.take)(data, {
    message: import_smithy_client.expectString
  });
  Object.assign(contents, doc);
  const exception = new NotFoundException({
    $metadata: deserializeMetadata(parsedOutput),
    ...contents
  });
  return (0, import_smithy_client.decorateServiceException)(exception, parsedOutput.body);
}, "de_NotFoundExceptionRes");
var de_SendingPausedExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const contents = (0, import_smithy_client.map)({});
  const data = parsedOutput.body;
  const doc = (0, import_smithy_client.take)(data, {
    message: import_smithy_client.expectString
  });
  Object.assign(contents, doc);
  const exception = new SendingPausedException({
    $metadata: deserializeMetadata(parsedOutput),
    ...contents
  });
  return (0, import_smithy_client.decorateServiceException)(exception, parsedOutput.body);
}, "de_SendingPausedExceptionRes");
var de_TooManyRequestsExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const contents = (0, import_smithy_client.map)({});
  const data = parsedOutput.body;
  const doc = (0, import_smithy_client.take)(data, {
    message: import_smithy_client.expectString
  });
  Object.assign(contents, doc);
  const exception = new TooManyRequestsException({
    $metadata: deserializeMetadata(parsedOutput),
    ...contents
  });
  return (0, import_smithy_client.decorateServiceException)(exception, parsedOutput.body);
}, "de_TooManyRequestsExceptionRes");
var se_Attachment = /* @__PURE__ */ __name((input, context) => {
  return (0, import_smithy_client.take)(input, {
    ContentDescription: [],
    ContentDisposition: [],
    ContentId: [],
    ContentTransferEncoding: [],
    ContentType: [],
    FileName: [],
    RawContent: context.base64Encoder
  });
}, "se_Attachment");
var se_AttachmentList = /* @__PURE__ */ __name((input, context) => {
  return input.filter((e) => e != null).map((entry) => {
    return se_Attachment(entry, context);
  });
}, "se_AttachmentList");
var se_BatchGetMetricDataQueries = /* @__PURE__ */ __name((input, context) => {
  return input.filter((e) => e != null).map((entry) => {
    return se_BatchGetMetricDataQuery(entry, context);
  });
}, "se_BatchGetMetricDataQueries");
var se_BatchGetMetricDataQuery = /* @__PURE__ */ __name((input, context) => {
  return (0, import_smithy_client.take)(input, {
    Dimensions: import_smithy_client._json,
    EndDate: /* @__PURE__ */ __name((_) => _.getTime() / 1e3, "EndDate"),
    Id: [],
    Metric: [],
    Namespace: [],
    StartDate: /* @__PURE__ */ __name((_) => _.getTime() / 1e3, "StartDate")
  });
}, "se_BatchGetMetricDataQuery");
var se_BulkEmailContent = /* @__PURE__ */ __name((input, context) => {
  return (0, import_smithy_client.take)(input, {
    Template: /* @__PURE__ */ __name((_) => se_Template(_, context), "Template")
  });
}, "se_BulkEmailContent");
var se_DomainDeliverabilityTrackingOption = /* @__PURE__ */ __name((input, context) => {
  return (0, import_smithy_client.take)(input, {
    Domain: [],
    InboxPlacementTrackingOption: import_smithy_client._json,
    SubscriptionStartDate: /* @__PURE__ */ __name((_) => _.getTime() / 1e3, "SubscriptionStartDate")
  });
}, "se_DomainDeliverabilityTrackingOption");
var se_DomainDeliverabilityTrackingOptions = /* @__PURE__ */ __name((input, context) => {
  return input.filter((e) => e != null).map((entry) => {
    return se_DomainDeliverabilityTrackingOption(entry, context);
  });
}, "se_DomainDeliverabilityTrackingOptions");
var se_EmailContent = /* @__PURE__ */ __name((input, context) => {
  return (0, import_smithy_client.take)(input, {
    Raw: /* @__PURE__ */ __name((_) => se_RawMessage(_, context), "Raw"),
    Simple: /* @__PURE__ */ __name((_) => se_Message(_, context), "Simple"),
    Template: /* @__PURE__ */ __name((_) => se_Template(_, context), "Template")
  });
}, "se_EmailContent");
var se_ExportDataSource = /* @__PURE__ */ __name((input, context) => {
  return (0, import_smithy_client.take)(input, {
    MessageInsightsDataSource: /* @__PURE__ */ __name((_) => se_MessageInsightsDataSource(_, context), "MessageInsightsDataSource"),
    MetricsDataSource: /* @__PURE__ */ __name((_) => se_MetricsDataSource(_, context), "MetricsDataSource")
  });
}, "se_ExportDataSource");
var se_Message = /* @__PURE__ */ __name((input, context) => {
  return (0, import_smithy_client.take)(input, {
    Attachments: /* @__PURE__ */ __name((_) => se_AttachmentList(_, context), "Attachments"),
    Body: import_smithy_client._json,
    Headers: import_smithy_client._json,
    Subject: import_smithy_client._json
  });
}, "se_Message");
var se_MessageInsightsDataSource = /* @__PURE__ */ __name((input, context) => {
  return (0, import_smithy_client.take)(input, {
    EndDate: /* @__PURE__ */ __name((_) => _.getTime() / 1e3, "EndDate"),
    Exclude: import_smithy_client._json,
    Include: import_smithy_client._json,
    MaxResults: [],
    StartDate: /* @__PURE__ */ __name((_) => _.getTime() / 1e3, "StartDate")
  });
}, "se_MessageInsightsDataSource");
var se_MetricsDataSource = /* @__PURE__ */ __name((input, context) => {
  return (0, import_smithy_client.take)(input, {
    Dimensions: import_smithy_client._json,
    EndDate: /* @__PURE__ */ __name((_) => _.getTime() / 1e3, "EndDate"),
    Metrics: import_smithy_client._json,
    Namespace: [],
    StartDate: /* @__PURE__ */ __name((_) => _.getTime() / 1e3, "StartDate")
  });
}, "se_MetricsDataSource");
var se_RawMessage = /* @__PURE__ */ __name((input, context) => {
  return (0, import_smithy_client.take)(input, {
    Data: context.base64Encoder
  });
}, "se_RawMessage");
var se_ReputationOptions = /* @__PURE__ */ __name((input, context) => {
  return (0, import_smithy_client.take)(input, {
    LastFreshStart: /* @__PURE__ */ __name((_) => _.getTime() / 1e3, "LastFreshStart"),
    ReputationMetricsEnabled: []
  });
}, "se_ReputationOptions");
var se_Template = /* @__PURE__ */ __name((input, context) => {
  return (0, import_smithy_client.take)(input, {
    Attachments: /* @__PURE__ */ __name((_) => se_AttachmentList(_, context), "Attachments"),
    Headers: import_smithy_client._json,
    TemplateArn: [],
    TemplateContent: import_smithy_client._json,
    TemplateData: [],
    TemplateName: []
  });
}, "se_Template");
var de_BlacklistEntries = /* @__PURE__ */ __name((output, context) => {
  const retVal = (output || []).filter((e) => e != null).map((entry) => {
    return de_BlacklistEntry(entry, context);
  });
  return retVal;
}, "de_BlacklistEntries");
var de_BlacklistEntry = /* @__PURE__ */ __name((output, context) => {
  return (0, import_smithy_client.take)(output, {
    Description: import_smithy_client.expectString,
    ListingTime: /* @__PURE__ */ __name((_) => (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseEpochTimestamp)((0, import_smithy_client.expectNumber)(_))), "ListingTime"),
    RblName: import_smithy_client.expectString
  });
}, "de_BlacklistEntry");
var de_BlacklistReport = /* @__PURE__ */ __name((output, context) => {
  return Object.entries(output).reduce((acc, [key, value]) => {
    if (value === null) {
      return acc;
    }
    acc[key] = de_BlacklistEntries(value, context);
    return acc;
  }, {});
}, "de_BlacklistReport");
var de_Contact = /* @__PURE__ */ __name((output, context) => {
  return (0, import_smithy_client.take)(output, {
    EmailAddress: import_smithy_client.expectString,
    LastUpdatedTimestamp: /* @__PURE__ */ __name((_) => (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseEpochTimestamp)((0, import_smithy_client.expectNumber)(_))), "LastUpdatedTimestamp"),
    TopicDefaultPreferences: import_smithy_client._json,
    TopicPreferences: import_smithy_client._json,
    UnsubscribeAll: import_smithy_client.expectBoolean
  });
}, "de_Contact");
var de_ContactList = /* @__PURE__ */ __name((output, context) => {
  return (0, import_smithy_client.take)(output, {
    ContactListName: import_smithy_client.expectString,
    LastUpdatedTimestamp: /* @__PURE__ */ __name((_) => (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseEpochTimestamp)((0, import_smithy_client.expectNumber)(_))), "LastUpdatedTimestamp")
  });
}, "de_ContactList");
var de_DailyVolume = /* @__PURE__ */ __name((output, context) => {
  return (0, import_smithy_client.take)(output, {
    DomainIspPlacements: /* @__PURE__ */ __name((_) => de_DomainIspPlacements(_, context), "DomainIspPlacements"),
    StartDate: /* @__PURE__ */ __name((_) => (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseEpochTimestamp)((0, import_smithy_client.expectNumber)(_))), "StartDate"),
    VolumeStatistics: import_smithy_client._json
  });
}, "de_DailyVolume");
var de_DailyVolumes = /* @__PURE__ */ __name((output, context) => {
  const retVal = (output || []).filter((e) => e != null).map((entry) => {
    return de_DailyVolume(entry, context);
  });
  return retVal;
}, "de_DailyVolumes");
var de_DeliverabilityTestReport = /* @__PURE__ */ __name((output, context) => {
  return (0, import_smithy_client.take)(output, {
    CreateDate: /* @__PURE__ */ __name((_) => (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseEpochTimestamp)((0, import_smithy_client.expectNumber)(_))), "CreateDate"),
    DeliverabilityTestStatus: import_smithy_client.expectString,
    FromEmailAddress: import_smithy_client.expectString,
    ReportId: import_smithy_client.expectString,
    ReportName: import_smithy_client.expectString,
    Subject: import_smithy_client.expectString
  });
}, "de_DeliverabilityTestReport");
var de_DeliverabilityTestReports = /* @__PURE__ */ __name((output, context) => {
  const retVal = (output || []).filter((e) => e != null).map((entry) => {
    return de_DeliverabilityTestReport(entry, context);
  });
  return retVal;
}, "de_DeliverabilityTestReports");
var de_DkimAttributes = /* @__PURE__ */ __name((output, context) => {
  return (0, import_smithy_client.take)(output, {
    CurrentSigningKeyLength: import_smithy_client.expectString,
    LastKeyGenerationTimestamp: /* @__PURE__ */ __name((_) => (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseEpochTimestamp)((0, import_smithy_client.expectNumber)(_))), "LastKeyGenerationTimestamp"),
    NextSigningKeyLength: import_smithy_client.expectString,
    SigningAttributesOrigin: import_smithy_client.expectString,
    SigningEnabled: import_smithy_client.expectBoolean,
    Status: import_smithy_client.expectString,
    Tokens: import_smithy_client._json
  });
}, "de_DkimAttributes");
var de_DomainDeliverabilityCampaign = /* @__PURE__ */ __name((output, context) => {
  return (0, import_smithy_client.take)(output, {
    CampaignId: import_smithy_client.expectString,
    DeleteRate: import_smithy_client.limitedParseDouble,
    Esps: import_smithy_client._json,
    FirstSeenDateTime: /* @__PURE__ */ __name((_) => (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseEpochTimestamp)((0, import_smithy_client.expectNumber)(_))), "FirstSeenDateTime"),
    FromAddress: import_smithy_client.expectString,
    ImageUrl: import_smithy_client.expectString,
    InboxCount: import_smithy_client.expectLong,
    LastSeenDateTime: /* @__PURE__ */ __name((_) => (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseEpochTimestamp)((0, import_smithy_client.expectNumber)(_))), "LastSeenDateTime"),
    ProjectedVolume: import_smithy_client.expectLong,
    ReadDeleteRate: import_smithy_client.limitedParseDouble,
    ReadRate: import_smithy_client.limitedParseDouble,
    SendingIps: import_smithy_client._json,
    SpamCount: import_smithy_client.expectLong,
    Subject: import_smithy_client.expectString
  });
}, "de_DomainDeliverabilityCampaign");
var de_DomainDeliverabilityCampaignList = /* @__PURE__ */ __name((output, context) => {
  const retVal = (output || []).filter((e) => e != null).map((entry) => {
    return de_DomainDeliverabilityCampaign(entry, context);
  });
  return retVal;
}, "de_DomainDeliverabilityCampaignList");
var de_DomainDeliverabilityTrackingOption = /* @__PURE__ */ __name((output, context) => {
  return (0, import_smithy_client.take)(output, {
    Domain: import_smithy_client.expectString,
    InboxPlacementTrackingOption: import_smithy_client._json,
    SubscriptionStartDate: /* @__PURE__ */ __name((_) => (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseEpochTimestamp)((0, import_smithy_client.expectNumber)(_))), "SubscriptionStartDate")
  });
}, "de_DomainDeliverabilityTrackingOption");
var de_DomainDeliverabilityTrackingOptions = /* @__PURE__ */ __name((output, context) => {
  const retVal = (output || []).filter((e) => e != null).map((entry) => {
    return de_DomainDeliverabilityTrackingOption(entry, context);
  });
  return retVal;
}, "de_DomainDeliverabilityTrackingOptions");
var de_DomainIspPlacement = /* @__PURE__ */ __name((output, context) => {
  return (0, import_smithy_client.take)(output, {
    InboxPercentage: import_smithy_client.limitedParseDouble,
    InboxRawCount: import_smithy_client.expectLong,
    IspName: import_smithy_client.expectString,
    SpamPercentage: import_smithy_client.limitedParseDouble,
    SpamRawCount: import_smithy_client.expectLong
  });
}, "de_DomainIspPlacement");
var de_DomainIspPlacements = /* @__PURE__ */ __name((output, context) => {
  const retVal = (output || []).filter((e) => e != null).map((entry) => {
    return de_DomainIspPlacement(entry, context);
  });
  return retVal;
}, "de_DomainIspPlacements");
var de_EmailInsights = /* @__PURE__ */ __name((output, context) => {
  return (0, import_smithy_client.take)(output, {
    Destination: import_smithy_client.expectString,
    Events: /* @__PURE__ */ __name((_) => de_InsightsEvents(_, context), "Events"),
    Isp: import_smithy_client.expectString
  });
}, "de_EmailInsights");
var de_EmailInsightsList = /* @__PURE__ */ __name((output, context) => {
  const retVal = (output || []).filter((e) => e != null).map((entry) => {
    return de_EmailInsights(entry, context);
  });
  return retVal;
}, "de_EmailInsightsList");
var de_EmailTemplateMetadata = /* @__PURE__ */ __name((output, context) => {
  return (0, import_smithy_client.take)(output, {
    CreatedTimestamp: /* @__PURE__ */ __name((_) => (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseEpochTimestamp)((0, import_smithy_client.expectNumber)(_))), "CreatedTimestamp"),
    TemplateName: import_smithy_client.expectString
  });
}, "de_EmailTemplateMetadata");
var de_EmailTemplateMetadataList = /* @__PURE__ */ __name((output, context) => {
  const retVal = (output || []).filter((e) => e != null).map((entry) => {
    return de_EmailTemplateMetadata(entry, context);
  });
  return retVal;
}, "de_EmailTemplateMetadataList");
var de_ExportDataSource = /* @__PURE__ */ __name((output, context) => {
  return (0, import_smithy_client.take)(output, {
    MessageInsightsDataSource: /* @__PURE__ */ __name((_) => de_MessageInsightsDataSource(_, context), "MessageInsightsDataSource"),
    MetricsDataSource: /* @__PURE__ */ __name((_) => de_MetricsDataSource(_, context), "MetricsDataSource")
  });
}, "de_ExportDataSource");
var de_ExportJobSummary = /* @__PURE__ */ __name((output, context) => {
  return (0, import_smithy_client.take)(output, {
    CompletedTimestamp: /* @__PURE__ */ __name((_) => (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseEpochTimestamp)((0, import_smithy_client.expectNumber)(_))), "CompletedTimestamp"),
    CreatedTimestamp: /* @__PURE__ */ __name((_) => (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseEpochTimestamp)((0, import_smithy_client.expectNumber)(_))), "CreatedTimestamp"),
    ExportSourceType: import_smithy_client.expectString,
    JobId: import_smithy_client.expectString,
    JobStatus: import_smithy_client.expectString
  });
}, "de_ExportJobSummary");
var de_ExportJobSummaryList = /* @__PURE__ */ __name((output, context) => {
  const retVal = (output || []).filter((e) => e != null).map((entry) => {
    return de_ExportJobSummary(entry, context);
  });
  return retVal;
}, "de_ExportJobSummaryList");
var de_ImportJobSummary = /* @__PURE__ */ __name((output, context) => {
  return (0, import_smithy_client.take)(output, {
    CreatedTimestamp: /* @__PURE__ */ __name((_) => (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseEpochTimestamp)((0, import_smithy_client.expectNumber)(_))), "CreatedTimestamp"),
    FailedRecordsCount: import_smithy_client.expectInt32,
    ImportDestination: import_smithy_client._json,
    JobId: import_smithy_client.expectString,
    JobStatus: import_smithy_client.expectString,
    ProcessedRecordsCount: import_smithy_client.expectInt32
  });
}, "de_ImportJobSummary");
var de_ImportJobSummaryList = /* @__PURE__ */ __name((output, context) => {
  const retVal = (output || []).filter((e) => e != null).map((entry) => {
    return de_ImportJobSummary(entry, context);
  });
  return retVal;
}, "de_ImportJobSummaryList");
var de_InsightsEvent = /* @__PURE__ */ __name((output, context) => {
  return (0, import_smithy_client.take)(output, {
    Details: import_smithy_client._json,
    Timestamp: /* @__PURE__ */ __name((_) => (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseEpochTimestamp)((0, import_smithy_client.expectNumber)(_))), "Timestamp"),
    Type: import_smithy_client.expectString
  });
}, "de_InsightsEvent");
var de_InsightsEvents = /* @__PURE__ */ __name((output, context) => {
  const retVal = (output || []).filter((e) => e != null).map((entry) => {
    return de_InsightsEvent(entry, context);
  });
  return retVal;
}, "de_InsightsEvents");
var de_IspPlacement = /* @__PURE__ */ __name((output, context) => {
  return (0, import_smithy_client.take)(output, {
    IspName: import_smithy_client.expectString,
    PlacementStatistics: /* @__PURE__ */ __name((_) => de_PlacementStatistics(_, context), "PlacementStatistics")
  });
}, "de_IspPlacement");
var de_IspPlacements = /* @__PURE__ */ __name((output, context) => {
  const retVal = (output || []).filter((e) => e != null).map((entry) => {
    return de_IspPlacement(entry, context);
  });
  return retVal;
}, "de_IspPlacements");
var de_ListOfContactLists = /* @__PURE__ */ __name((output, context) => {
  const retVal = (output || []).filter((e) => e != null).map((entry) => {
    return de_ContactList(entry, context);
  });
  return retVal;
}, "de_ListOfContactLists");
var de_ListOfContacts = /* @__PURE__ */ __name((output, context) => {
  const retVal = (output || []).filter((e) => e != null).map((entry) => {
    return de_Contact(entry, context);
  });
  return retVal;
}, "de_ListOfContacts");
var de_MessageInsightsDataSource = /* @__PURE__ */ __name((output, context) => {
  return (0, import_smithy_client.take)(output, {
    EndDate: /* @__PURE__ */ __name((_) => (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseEpochTimestamp)((0, import_smithy_client.expectNumber)(_))), "EndDate"),
    Exclude: import_smithy_client._json,
    Include: import_smithy_client._json,
    MaxResults: import_smithy_client.expectInt32,
    StartDate: /* @__PURE__ */ __name((_) => (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseEpochTimestamp)((0, import_smithy_client.expectNumber)(_))), "StartDate")
  });
}, "de_MessageInsightsDataSource");
var de_MetricDataResult = /* @__PURE__ */ __name((output, context) => {
  return (0, import_smithy_client.take)(output, {
    Id: import_smithy_client.expectString,
    Timestamps: /* @__PURE__ */ __name((_) => de_TimestampList(_, context), "Timestamps"),
    Values: import_smithy_client._json
  });
}, "de_MetricDataResult");
var de_MetricDataResultList = /* @__PURE__ */ __name((output, context) => {
  const retVal = (output || []).filter((e) => e != null).map((entry) => {
    return de_MetricDataResult(entry, context);
  });
  return retVal;
}, "de_MetricDataResultList");
var de_MetricsDataSource = /* @__PURE__ */ __name((output, context) => {
  return (0, import_smithy_client.take)(output, {
    Dimensions: import_smithy_client._json,
    EndDate: /* @__PURE__ */ __name((_) => (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseEpochTimestamp)((0, import_smithy_client.expectNumber)(_))), "EndDate"),
    Metrics: import_smithy_client._json,
    Namespace: import_smithy_client.expectString,
    StartDate: /* @__PURE__ */ __name((_) => (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseEpochTimestamp)((0, import_smithy_client.expectNumber)(_))), "StartDate")
  });
}, "de_MetricsDataSource");
var de_MultiRegionEndpoint = /* @__PURE__ */ __name((output, context) => {
  return (0, import_smithy_client.take)(output, {
    CreatedTimestamp: /* @__PURE__ */ __name((_) => (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseEpochTimestamp)((0, import_smithy_client.expectNumber)(_))), "CreatedTimestamp"),
    EndpointId: import_smithy_client.expectString,
    EndpointName: import_smithy_client.expectString,
    LastUpdatedTimestamp: /* @__PURE__ */ __name((_) => (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseEpochTimestamp)((0, import_smithy_client.expectNumber)(_))), "LastUpdatedTimestamp"),
    Regions: import_smithy_client._json,
    Status: import_smithy_client.expectString
  });
}, "de_MultiRegionEndpoint");
var de_MultiRegionEndpoints = /* @__PURE__ */ __name((output, context) => {
  const retVal = (output || []).filter((e) => e != null).map((entry) => {
    return de_MultiRegionEndpoint(entry, context);
  });
  return retVal;
}, "de_MultiRegionEndpoints");
var de_OverallVolume = /* @__PURE__ */ __name((output, context) => {
  return (0, import_smithy_client.take)(output, {
    DomainIspPlacements: /* @__PURE__ */ __name((_) => de_DomainIspPlacements(_, context), "DomainIspPlacements"),
    ReadRatePercent: import_smithy_client.limitedParseDouble,
    VolumeStatistics: import_smithy_client._json
  });
}, "de_OverallVolume");
var de_PlacementStatistics = /* @__PURE__ */ __name((output, context) => {
  return (0, import_smithy_client.take)(output, {
    DkimPercentage: import_smithy_client.limitedParseDouble,
    InboxPercentage: import_smithy_client.limitedParseDouble,
    MissingPercentage: import_smithy_client.limitedParseDouble,
    SpamPercentage: import_smithy_client.limitedParseDouble,
    SpfPercentage: import_smithy_client.limitedParseDouble
  });
}, "de_PlacementStatistics");
var de_Recommendation = /* @__PURE__ */ __name((output, context) => {
  return (0, import_smithy_client.take)(output, {
    CreatedTimestamp: /* @__PURE__ */ __name((_) => (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseEpochTimestamp)((0, import_smithy_client.expectNumber)(_))), "CreatedTimestamp"),
    Description: import_smithy_client.expectString,
    Impact: import_smithy_client.expectString,
    LastUpdatedTimestamp: /* @__PURE__ */ __name((_) => (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseEpochTimestamp)((0, import_smithy_client.expectNumber)(_))), "LastUpdatedTimestamp"),
    ResourceArn: import_smithy_client.expectString,
    Status: import_smithy_client.expectString,
    Type: import_smithy_client.expectString
  });
}, "de_Recommendation");
var de_RecommendationsList = /* @__PURE__ */ __name((output, context) => {
  const retVal = (output || []).filter((e) => e != null).map((entry) => {
    return de_Recommendation(entry, context);
  });
  return retVal;
}, "de_RecommendationsList");
var de_ReputationEntitiesList = /* @__PURE__ */ __name((output, context) => {
  const retVal = (output || []).filter((e) => e != null).map((entry) => {
    return de_ReputationEntity(entry, context);
  });
  return retVal;
}, "de_ReputationEntitiesList");
var de_ReputationEntity = /* @__PURE__ */ __name((output, context) => {
  return (0, import_smithy_client.take)(output, {
    AwsSesManagedStatus: /* @__PURE__ */ __name((_) => de_StatusRecord(_, context), "AwsSesManagedStatus"),
    CustomerManagedStatus: /* @__PURE__ */ __name((_) => de_StatusRecord(_, context), "CustomerManagedStatus"),
    ReputationEntityReference: import_smithy_client.expectString,
    ReputationEntityType: import_smithy_client.expectString,
    ReputationImpact: import_smithy_client.expectString,
    ReputationManagementPolicy: import_smithy_client.expectString,
    SendingStatusAggregate: import_smithy_client.expectString
  });
}, "de_ReputationEntity");
var de_ReputationOptions = /* @__PURE__ */ __name((output, context) => {
  return (0, import_smithy_client.take)(output, {
    LastFreshStart: /* @__PURE__ */ __name((_) => (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseEpochTimestamp)((0, import_smithy_client.expectNumber)(_))), "LastFreshStart"),
    ReputationMetricsEnabled: import_smithy_client.expectBoolean
  });
}, "de_ReputationOptions");
var de_ResourceTenantMetadata = /* @__PURE__ */ __name((output, context) => {
  return (0, import_smithy_client.take)(output, {
    AssociatedTimestamp: /* @__PURE__ */ __name((_) => (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseEpochTimestamp)((0, import_smithy_client.expectNumber)(_))), "AssociatedTimestamp"),
    ResourceArn: import_smithy_client.expectString,
    TenantId: import_smithy_client.expectString,
    TenantName: import_smithy_client.expectString
  });
}, "de_ResourceTenantMetadata");
var de_ResourceTenantMetadataList = /* @__PURE__ */ __name((output, context) => {
  const retVal = (output || []).filter((e) => e != null).map((entry) => {
    return de_ResourceTenantMetadata(entry, context);
  });
  return retVal;
}, "de_ResourceTenantMetadataList");
var de_SendQuota = /* @__PURE__ */ __name((output, context) => {
  return (0, import_smithy_client.take)(output, {
    Max24HourSend: import_smithy_client.limitedParseDouble,
    MaxSendRate: import_smithy_client.limitedParseDouble,
    SentLast24Hours: import_smithy_client.limitedParseDouble
  });
}, "de_SendQuota");
var de_StatusRecord = /* @__PURE__ */ __name((output, context) => {
  return (0, import_smithy_client.take)(output, {
    Cause: import_smithy_client.expectString,
    LastUpdatedTimestamp: /* @__PURE__ */ __name((_) => (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseEpochTimestamp)((0, import_smithy_client.expectNumber)(_))), "LastUpdatedTimestamp"),
    Status: import_smithy_client.expectString
  });
}, "de_StatusRecord");
var de_SuppressedDestination = /* @__PURE__ */ __name((output, context) => {
  return (0, import_smithy_client.take)(output, {
    Attributes: import_smithy_client._json,
    EmailAddress: import_smithy_client.expectString,
    LastUpdateTime: /* @__PURE__ */ __name((_) => (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseEpochTimestamp)((0, import_smithy_client.expectNumber)(_))), "LastUpdateTime"),
    Reason: import_smithy_client.expectString
  });
}, "de_SuppressedDestination");
var de_SuppressedDestinationSummaries = /* @__PURE__ */ __name((output, context) => {
  const retVal = (output || []).filter((e) => e != null).map((entry) => {
    return de_SuppressedDestinationSummary(entry, context);
  });
  return retVal;
}, "de_SuppressedDestinationSummaries");
var de_SuppressedDestinationSummary = /* @__PURE__ */ __name((output, context) => {
  return (0, import_smithy_client.take)(output, {
    EmailAddress: import_smithy_client.expectString,
    LastUpdateTime: /* @__PURE__ */ __name((_) => (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseEpochTimestamp)((0, import_smithy_client.expectNumber)(_))), "LastUpdateTime"),
    Reason: import_smithy_client.expectString
  });
}, "de_SuppressedDestinationSummary");
var de_Tenant = /* @__PURE__ */ __name((output, context) => {
  return (0, import_smithy_client.take)(output, {
    CreatedTimestamp: /* @__PURE__ */ __name((_) => (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseEpochTimestamp)((0, import_smithy_client.expectNumber)(_))), "CreatedTimestamp"),
    SendingStatus: import_smithy_client.expectString,
    Tags: import_smithy_client._json,
    TenantArn: import_smithy_client.expectString,
    TenantId: import_smithy_client.expectString,
    TenantName: import_smithy_client.expectString
  });
}, "de_Tenant");
var de_TenantInfo = /* @__PURE__ */ __name((output, context) => {
  return (0, import_smithy_client.take)(output, {
    CreatedTimestamp: /* @__PURE__ */ __name((_) => (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseEpochTimestamp)((0, import_smithy_client.expectNumber)(_))), "CreatedTimestamp"),
    TenantArn: import_smithy_client.expectString,
    TenantId: import_smithy_client.expectString,
    TenantName: import_smithy_client.expectString
  });
}, "de_TenantInfo");
var de_TenantInfoList = /* @__PURE__ */ __name((output, context) => {
  const retVal = (output || []).filter((e) => e != null).map((entry) => {
    return de_TenantInfo(entry, context);
  });
  return retVal;
}, "de_TenantInfoList");
var de_TimestampList = /* @__PURE__ */ __name((output, context) => {
  const retVal = (output || []).filter((e) => e != null).map((entry) => {
    return (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseEpochTimestamp)((0, import_smithy_client.expectNumber)(entry)));
  });
  return retVal;
}, "de_TimestampList");
var de_VerificationInfo = /* @__PURE__ */ __name((output, context) => {
  return (0, import_smithy_client.take)(output, {
    ErrorType: import_smithy_client.expectString,
    LastCheckedTimestamp: /* @__PURE__ */ __name((_) => (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseEpochTimestamp)((0, import_smithy_client.expectNumber)(_))), "LastCheckedTimestamp"),
    LastSuccessTimestamp: /* @__PURE__ */ __name((_) => (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseEpochTimestamp)((0, import_smithy_client.expectNumber)(_))), "LastSuccessTimestamp"),
    SOARecord: import_smithy_client._json
  });
}, "de_VerificationInfo");
var deserializeMetadata = /* @__PURE__ */ __name((output) => ({
  httpStatusCode: output.statusCode,
  requestId: output.headers["x-amzn-requestid"] ?? output.headers["x-amzn-request-id"] ?? output.headers["x-amz-request-id"],
  extendedRequestId: output.headers["x-amz-id-2"],
  cfId: output.headers["x-amz-cf-id"]
}), "deserializeMetadata");
var _BIN = "BlacklistItemNames";
var _ED = "EndDate";
var _NT = "NextToken";
var _PN = "PoolName";
var _PS = "PageSize";
var _R = "Reasons";
var _RA = "ResourceArn";
var _Re = "Reason";
var _SD = "StartDate";
var _TK = "TagKeys";

// src/commands/BatchGetMetricDataCommand.ts
var BatchGetMetricDataCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "BatchGetMetricData", {}).n("SESv2Client", "BatchGetMetricDataCommand").f(void 0, void 0).ser(se_BatchGetMetricDataCommand).de(de_BatchGetMetricDataCommand).build() {
  static {
    __name(this, "BatchGetMetricDataCommand");
  }
};

// src/commands/CancelExportJobCommand.ts



var CancelExportJobCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "CancelExportJob", {}).n("SESv2Client", "CancelExportJobCommand").f(void 0, void 0).ser(se_CancelExportJobCommand).de(de_CancelExportJobCommand).build() {
  static {
    __name(this, "CancelExportJobCommand");
  }
};

// src/commands/CreateConfigurationSetCommand.ts



var CreateConfigurationSetCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "CreateConfigurationSet", {}).n("SESv2Client", "CreateConfigurationSetCommand").f(void 0, void 0).ser(se_CreateConfigurationSetCommand).de(de_CreateConfigurationSetCommand).build() {
  static {
    __name(this, "CreateConfigurationSetCommand");
  }
};

// src/commands/CreateConfigurationSetEventDestinationCommand.ts



var CreateConfigurationSetEventDestinationCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "CreateConfigurationSetEventDestination", {}).n("SESv2Client", "CreateConfigurationSetEventDestinationCommand").f(void 0, void 0).ser(se_CreateConfigurationSetEventDestinationCommand).de(de_CreateConfigurationSetEventDestinationCommand).build() {
  static {
    __name(this, "CreateConfigurationSetEventDestinationCommand");
  }
};

// src/commands/CreateContactCommand.ts



var CreateContactCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "CreateContact", {}).n("SESv2Client", "CreateContactCommand").f(void 0, void 0).ser(se_CreateContactCommand).de(de_CreateContactCommand).build() {
  static {
    __name(this, "CreateContactCommand");
  }
};

// src/commands/CreateContactListCommand.ts



var CreateContactListCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "CreateContactList", {}).n("SESv2Client", "CreateContactListCommand").f(void 0, void 0).ser(se_CreateContactListCommand).de(de_CreateContactListCommand).build() {
  static {
    __name(this, "CreateContactListCommand");
  }
};

// src/commands/CreateCustomVerificationEmailTemplateCommand.ts



var CreateCustomVerificationEmailTemplateCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "CreateCustomVerificationEmailTemplate", {}).n("SESv2Client", "CreateCustomVerificationEmailTemplateCommand").f(void 0, void 0).ser(se_CreateCustomVerificationEmailTemplateCommand).de(de_CreateCustomVerificationEmailTemplateCommand).build() {
  static {
    __name(this, "CreateCustomVerificationEmailTemplateCommand");
  }
};

// src/commands/CreateDedicatedIpPoolCommand.ts



var CreateDedicatedIpPoolCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "CreateDedicatedIpPool", {}).n("SESv2Client", "CreateDedicatedIpPoolCommand").f(void 0, void 0).ser(se_CreateDedicatedIpPoolCommand).de(de_CreateDedicatedIpPoolCommand).build() {
  static {
    __name(this, "CreateDedicatedIpPoolCommand");
  }
};

// src/commands/CreateDeliverabilityTestReportCommand.ts



var CreateDeliverabilityTestReportCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "CreateDeliverabilityTestReport", {}).n("SESv2Client", "CreateDeliverabilityTestReportCommand").f(void 0, void 0).ser(se_CreateDeliverabilityTestReportCommand).de(de_CreateDeliverabilityTestReportCommand).build() {
  static {
    __name(this, "CreateDeliverabilityTestReportCommand");
  }
};

// src/commands/CreateEmailIdentityCommand.ts



var CreateEmailIdentityCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "CreateEmailIdentity", {}).n("SESv2Client", "CreateEmailIdentityCommand").f(CreateEmailIdentityRequestFilterSensitiveLog, void 0).ser(se_CreateEmailIdentityCommand).de(de_CreateEmailIdentityCommand).build() {
  static {
    __name(this, "CreateEmailIdentityCommand");
  }
};

// src/commands/CreateEmailIdentityPolicyCommand.ts



var CreateEmailIdentityPolicyCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "CreateEmailIdentityPolicy", {}).n("SESv2Client", "CreateEmailIdentityPolicyCommand").f(void 0, void 0).ser(se_CreateEmailIdentityPolicyCommand).de(de_CreateEmailIdentityPolicyCommand).build() {
  static {
    __name(this, "CreateEmailIdentityPolicyCommand");
  }
};

// src/commands/CreateEmailTemplateCommand.ts



var CreateEmailTemplateCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "CreateEmailTemplate", {}).n("SESv2Client", "CreateEmailTemplateCommand").f(void 0, void 0).ser(se_CreateEmailTemplateCommand).de(de_CreateEmailTemplateCommand).build() {
  static {
    __name(this, "CreateEmailTemplateCommand");
  }
};

// src/commands/CreateExportJobCommand.ts



var CreateExportJobCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "CreateExportJob", {}).n("SESv2Client", "CreateExportJobCommand").f(CreateExportJobRequestFilterSensitiveLog, void 0).ser(se_CreateExportJobCommand).de(de_CreateExportJobCommand).build() {
  static {
    __name(this, "CreateExportJobCommand");
  }
};

// src/commands/CreateImportJobCommand.ts



var CreateImportJobCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "CreateImportJob", {}).n("SESv2Client", "CreateImportJobCommand").f(void 0, void 0).ser(se_CreateImportJobCommand).de(de_CreateImportJobCommand).build() {
  static {
    __name(this, "CreateImportJobCommand");
  }
};

// src/commands/CreateMultiRegionEndpointCommand.ts



var CreateMultiRegionEndpointCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "CreateMultiRegionEndpoint", {}).n("SESv2Client", "CreateMultiRegionEndpointCommand").f(void 0, void 0).ser(se_CreateMultiRegionEndpointCommand).de(de_CreateMultiRegionEndpointCommand).build() {
  static {
    __name(this, "CreateMultiRegionEndpointCommand");
  }
};

// src/commands/CreateTenantCommand.ts



var CreateTenantCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "CreateTenant", {}).n("SESv2Client", "CreateTenantCommand").f(void 0, void 0).ser(se_CreateTenantCommand).de(de_CreateTenantCommand).build() {
  static {
    __name(this, "CreateTenantCommand");
  }
};

// src/commands/CreateTenantResourceAssociationCommand.ts



var CreateTenantResourceAssociationCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "CreateTenantResourceAssociation", {}).n("SESv2Client", "CreateTenantResourceAssociationCommand").f(void 0, void 0).ser(se_CreateTenantResourceAssociationCommand).de(de_CreateTenantResourceAssociationCommand).build() {
  static {
    __name(this, "CreateTenantResourceAssociationCommand");
  }
};

// src/commands/DeleteConfigurationSetCommand.ts



var DeleteConfigurationSetCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "DeleteConfigurationSet", {}).n("SESv2Client", "DeleteConfigurationSetCommand").f(void 0, void 0).ser(se_DeleteConfigurationSetCommand).de(de_DeleteConfigurationSetCommand).build() {
  static {
    __name(this, "DeleteConfigurationSetCommand");
  }
};

// src/commands/DeleteConfigurationSetEventDestinationCommand.ts



var DeleteConfigurationSetEventDestinationCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "DeleteConfigurationSetEventDestination", {}).n("SESv2Client", "DeleteConfigurationSetEventDestinationCommand").f(void 0, void 0).ser(se_DeleteConfigurationSetEventDestinationCommand).de(de_DeleteConfigurationSetEventDestinationCommand).build() {
  static {
    __name(this, "DeleteConfigurationSetEventDestinationCommand");
  }
};

// src/commands/DeleteContactCommand.ts



var DeleteContactCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "DeleteContact", {}).n("SESv2Client", "DeleteContactCommand").f(void 0, void 0).ser(se_DeleteContactCommand).de(de_DeleteContactCommand).build() {
  static {
    __name(this, "DeleteContactCommand");
  }
};

// src/commands/DeleteContactListCommand.ts



var DeleteContactListCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "DeleteContactList", {}).n("SESv2Client", "DeleteContactListCommand").f(void 0, void 0).ser(se_DeleteContactListCommand).de(de_DeleteContactListCommand).build() {
  static {
    __name(this, "DeleteContactListCommand");
  }
};

// src/commands/DeleteCustomVerificationEmailTemplateCommand.ts



var DeleteCustomVerificationEmailTemplateCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "DeleteCustomVerificationEmailTemplate", {}).n("SESv2Client", "DeleteCustomVerificationEmailTemplateCommand").f(void 0, void 0).ser(se_DeleteCustomVerificationEmailTemplateCommand).de(de_DeleteCustomVerificationEmailTemplateCommand).build() {
  static {
    __name(this, "DeleteCustomVerificationEmailTemplateCommand");
  }
};

// src/commands/DeleteDedicatedIpPoolCommand.ts



var DeleteDedicatedIpPoolCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "DeleteDedicatedIpPool", {}).n("SESv2Client", "DeleteDedicatedIpPoolCommand").f(void 0, void 0).ser(se_DeleteDedicatedIpPoolCommand).de(de_DeleteDedicatedIpPoolCommand).build() {
  static {
    __name(this, "DeleteDedicatedIpPoolCommand");
  }
};

// src/commands/DeleteEmailIdentityCommand.ts



var DeleteEmailIdentityCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "DeleteEmailIdentity", {}).n("SESv2Client", "DeleteEmailIdentityCommand").f(void 0, void 0).ser(se_DeleteEmailIdentityCommand).de(de_DeleteEmailIdentityCommand).build() {
  static {
    __name(this, "DeleteEmailIdentityCommand");
  }
};

// src/commands/DeleteEmailIdentityPolicyCommand.ts



var DeleteEmailIdentityPolicyCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "DeleteEmailIdentityPolicy", {}).n("SESv2Client", "DeleteEmailIdentityPolicyCommand").f(void 0, void 0).ser(se_DeleteEmailIdentityPolicyCommand).de(de_DeleteEmailIdentityPolicyCommand).build() {
  static {
    __name(this, "DeleteEmailIdentityPolicyCommand");
  }
};

// src/commands/DeleteEmailTemplateCommand.ts



var DeleteEmailTemplateCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "DeleteEmailTemplate", {}).n("SESv2Client", "DeleteEmailTemplateCommand").f(void 0, void 0).ser(se_DeleteEmailTemplateCommand).de(de_DeleteEmailTemplateCommand).build() {
  static {
    __name(this, "DeleteEmailTemplateCommand");
  }
};

// src/commands/DeleteMultiRegionEndpointCommand.ts



var DeleteMultiRegionEndpointCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "DeleteMultiRegionEndpoint", {}).n("SESv2Client", "DeleteMultiRegionEndpointCommand").f(void 0, void 0).ser(se_DeleteMultiRegionEndpointCommand).de(de_DeleteMultiRegionEndpointCommand).build() {
  static {
    __name(this, "DeleteMultiRegionEndpointCommand");
  }
};

// src/commands/DeleteSuppressedDestinationCommand.ts



var DeleteSuppressedDestinationCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "DeleteSuppressedDestination", {}).n("SESv2Client", "DeleteSuppressedDestinationCommand").f(void 0, void 0).ser(se_DeleteSuppressedDestinationCommand).de(de_DeleteSuppressedDestinationCommand).build() {
  static {
    __name(this, "DeleteSuppressedDestinationCommand");
  }
};

// src/commands/DeleteTenantCommand.ts



var DeleteTenantCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "DeleteTenant", {}).n("SESv2Client", "DeleteTenantCommand").f(void 0, void 0).ser(se_DeleteTenantCommand).de(de_DeleteTenantCommand).build() {
  static {
    __name(this, "DeleteTenantCommand");
  }
};

// src/commands/DeleteTenantResourceAssociationCommand.ts



var DeleteTenantResourceAssociationCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "DeleteTenantResourceAssociation", {}).n("SESv2Client", "DeleteTenantResourceAssociationCommand").f(void 0, void 0).ser(se_DeleteTenantResourceAssociationCommand).de(de_DeleteTenantResourceAssociationCommand).build() {
  static {
    __name(this, "DeleteTenantResourceAssociationCommand");
  }
};

// src/commands/GetAccountCommand.ts



var GetAccountCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "GetAccount", {}).n("SESv2Client", "GetAccountCommand").f(void 0, GetAccountResponseFilterSensitiveLog).ser(se_GetAccountCommand).de(de_GetAccountCommand).build() {
  static {
    __name(this, "GetAccountCommand");
  }
};

// src/commands/GetBlacklistReportsCommand.ts



var GetBlacklistReportsCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "GetBlacklistReports", {}).n("SESv2Client", "GetBlacklistReportsCommand").f(void 0, void 0).ser(se_GetBlacklistReportsCommand).de(de_GetBlacklistReportsCommand).build() {
  static {
    __name(this, "GetBlacklistReportsCommand");
  }
};

// src/commands/GetConfigurationSetCommand.ts



var GetConfigurationSetCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "GetConfigurationSet", {}).n("SESv2Client", "GetConfigurationSetCommand").f(void 0, void 0).ser(se_GetConfigurationSetCommand).de(de_GetConfigurationSetCommand).build() {
  static {
    __name(this, "GetConfigurationSetCommand");
  }
};

// src/commands/GetConfigurationSetEventDestinationsCommand.ts



var GetConfigurationSetEventDestinationsCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "GetConfigurationSetEventDestinations", {}).n("SESv2Client", "GetConfigurationSetEventDestinationsCommand").f(void 0, void 0).ser(se_GetConfigurationSetEventDestinationsCommand).de(de_GetConfigurationSetEventDestinationsCommand).build() {
  static {
    __name(this, "GetConfigurationSetEventDestinationsCommand");
  }
};

// src/commands/GetContactCommand.ts



var GetContactCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "GetContact", {}).n("SESv2Client", "GetContactCommand").f(void 0, void 0).ser(se_GetContactCommand).de(de_GetContactCommand).build() {
  static {
    __name(this, "GetContactCommand");
  }
};

// src/commands/GetContactListCommand.ts



var GetContactListCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "GetContactList", {}).n("SESv2Client", "GetContactListCommand").f(void 0, void 0).ser(se_GetContactListCommand).de(de_GetContactListCommand).build() {
  static {
    __name(this, "GetContactListCommand");
  }
};

// src/commands/GetCustomVerificationEmailTemplateCommand.ts



var GetCustomVerificationEmailTemplateCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "GetCustomVerificationEmailTemplate", {}).n("SESv2Client", "GetCustomVerificationEmailTemplateCommand").f(void 0, void 0).ser(se_GetCustomVerificationEmailTemplateCommand).de(de_GetCustomVerificationEmailTemplateCommand).build() {
  static {
    __name(this, "GetCustomVerificationEmailTemplateCommand");
  }
};

// src/commands/GetDedicatedIpCommand.ts



var GetDedicatedIpCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "GetDedicatedIp", {}).n("SESv2Client", "GetDedicatedIpCommand").f(void 0, void 0).ser(se_GetDedicatedIpCommand).de(de_GetDedicatedIpCommand).build() {
  static {
    __name(this, "GetDedicatedIpCommand");
  }
};

// src/commands/GetDedicatedIpPoolCommand.ts



var GetDedicatedIpPoolCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "GetDedicatedIpPool", {}).n("SESv2Client", "GetDedicatedIpPoolCommand").f(void 0, void 0).ser(se_GetDedicatedIpPoolCommand).de(de_GetDedicatedIpPoolCommand).build() {
  static {
    __name(this, "GetDedicatedIpPoolCommand");
  }
};

// src/commands/GetDedicatedIpsCommand.ts



var GetDedicatedIpsCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "GetDedicatedIps", {}).n("SESv2Client", "GetDedicatedIpsCommand").f(void 0, void 0).ser(se_GetDedicatedIpsCommand).de(de_GetDedicatedIpsCommand).build() {
  static {
    __name(this, "GetDedicatedIpsCommand");
  }
};

// src/commands/GetDeliverabilityDashboardOptionsCommand.ts



var GetDeliverabilityDashboardOptionsCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "GetDeliverabilityDashboardOptions", {}).n("SESv2Client", "GetDeliverabilityDashboardOptionsCommand").f(void 0, void 0).ser(se_GetDeliverabilityDashboardOptionsCommand).de(de_GetDeliverabilityDashboardOptionsCommand).build() {
  static {
    __name(this, "GetDeliverabilityDashboardOptionsCommand");
  }
};

// src/commands/GetDeliverabilityTestReportCommand.ts



var GetDeliverabilityTestReportCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "GetDeliverabilityTestReport", {}).n("SESv2Client", "GetDeliverabilityTestReportCommand").f(void 0, void 0).ser(se_GetDeliverabilityTestReportCommand).de(de_GetDeliverabilityTestReportCommand).build() {
  static {
    __name(this, "GetDeliverabilityTestReportCommand");
  }
};

// src/commands/GetDomainDeliverabilityCampaignCommand.ts



var GetDomainDeliverabilityCampaignCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "GetDomainDeliverabilityCampaign", {}).n("SESv2Client", "GetDomainDeliverabilityCampaignCommand").f(void 0, void 0).ser(se_GetDomainDeliverabilityCampaignCommand).de(de_GetDomainDeliverabilityCampaignCommand).build() {
  static {
    __name(this, "GetDomainDeliverabilityCampaignCommand");
  }
};

// src/commands/GetDomainStatisticsReportCommand.ts



var GetDomainStatisticsReportCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "GetDomainStatisticsReport", {}).n("SESv2Client", "GetDomainStatisticsReportCommand").f(void 0, void 0).ser(se_GetDomainStatisticsReportCommand).de(de_GetDomainStatisticsReportCommand).build() {
  static {
    __name(this, "GetDomainStatisticsReportCommand");
  }
};

// src/commands/GetEmailIdentityCommand.ts



var GetEmailIdentityCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "GetEmailIdentity", {}).n("SESv2Client", "GetEmailIdentityCommand").f(void 0, void 0).ser(se_GetEmailIdentityCommand).de(de_GetEmailIdentityCommand).build() {
  static {
    __name(this, "GetEmailIdentityCommand");
  }
};

// src/commands/GetEmailIdentityPoliciesCommand.ts



var GetEmailIdentityPoliciesCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "GetEmailIdentityPolicies", {}).n("SESv2Client", "GetEmailIdentityPoliciesCommand").f(void 0, void 0).ser(se_GetEmailIdentityPoliciesCommand).de(de_GetEmailIdentityPoliciesCommand).build() {
  static {
    __name(this, "GetEmailIdentityPoliciesCommand");
  }
};

// src/commands/GetEmailTemplateCommand.ts



var GetEmailTemplateCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "GetEmailTemplate", {}).n("SESv2Client", "GetEmailTemplateCommand").f(void 0, void 0).ser(se_GetEmailTemplateCommand).de(de_GetEmailTemplateCommand).build() {
  static {
    __name(this, "GetEmailTemplateCommand");
  }
};

// src/commands/GetExportJobCommand.ts



var GetExportJobCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "GetExportJob", {}).n("SESv2Client", "GetExportJobCommand").f(void 0, GetExportJobResponseFilterSensitiveLog).ser(se_GetExportJobCommand).de(de_GetExportJobCommand).build() {
  static {
    __name(this, "GetExportJobCommand");
  }
};

// src/commands/GetImportJobCommand.ts



var GetImportJobCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "GetImportJob", {}).n("SESv2Client", "GetImportJobCommand").f(void 0, void 0).ser(se_GetImportJobCommand).de(de_GetImportJobCommand).build() {
  static {
    __name(this, "GetImportJobCommand");
  }
};

// src/commands/GetMessageInsightsCommand.ts



var GetMessageInsightsCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "GetMessageInsights", {}).n("SESv2Client", "GetMessageInsightsCommand").f(void 0, GetMessageInsightsResponseFilterSensitiveLog).ser(se_GetMessageInsightsCommand).de(de_GetMessageInsightsCommand).build() {
  static {
    __name(this, "GetMessageInsightsCommand");
  }
};

// src/commands/GetMultiRegionEndpointCommand.ts



var GetMultiRegionEndpointCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "GetMultiRegionEndpoint", {}).n("SESv2Client", "GetMultiRegionEndpointCommand").f(void 0, void 0).ser(se_GetMultiRegionEndpointCommand).de(de_GetMultiRegionEndpointCommand).build() {
  static {
    __name(this, "GetMultiRegionEndpointCommand");
  }
};

// src/commands/GetReputationEntityCommand.ts



var GetReputationEntityCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "GetReputationEntity", {}).n("SESv2Client", "GetReputationEntityCommand").f(void 0, void 0).ser(se_GetReputationEntityCommand).de(de_GetReputationEntityCommand).build() {
  static {
    __name(this, "GetReputationEntityCommand");
  }
};

// src/commands/GetSuppressedDestinationCommand.ts



var GetSuppressedDestinationCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "GetSuppressedDestination", {}).n("SESv2Client", "GetSuppressedDestinationCommand").f(void 0, void 0).ser(se_GetSuppressedDestinationCommand).de(de_GetSuppressedDestinationCommand).build() {
  static {
    __name(this, "GetSuppressedDestinationCommand");
  }
};

// src/commands/GetTenantCommand.ts



var GetTenantCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "GetTenant", {}).n("SESv2Client", "GetTenantCommand").f(void 0, void 0).ser(se_GetTenantCommand).de(de_GetTenantCommand).build() {
  static {
    __name(this, "GetTenantCommand");
  }
};

// src/commands/ListConfigurationSetsCommand.ts



var ListConfigurationSetsCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "ListConfigurationSets", {}).n("SESv2Client", "ListConfigurationSetsCommand").f(void 0, void 0).ser(se_ListConfigurationSetsCommand).de(de_ListConfigurationSetsCommand).build() {
  static {
    __name(this, "ListConfigurationSetsCommand");
  }
};

// src/commands/ListContactListsCommand.ts



var ListContactListsCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "ListContactLists", {}).n("SESv2Client", "ListContactListsCommand").f(void 0, void 0).ser(se_ListContactListsCommand).de(de_ListContactListsCommand).build() {
  static {
    __name(this, "ListContactListsCommand");
  }
};

// src/commands/ListContactsCommand.ts



var ListContactsCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "ListContacts", {}).n("SESv2Client", "ListContactsCommand").f(void 0, void 0).ser(se_ListContactsCommand).de(de_ListContactsCommand).build() {
  static {
    __name(this, "ListContactsCommand");
  }
};

// src/commands/ListCustomVerificationEmailTemplatesCommand.ts



var ListCustomVerificationEmailTemplatesCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "ListCustomVerificationEmailTemplates", {}).n("SESv2Client", "ListCustomVerificationEmailTemplatesCommand").f(void 0, void 0).ser(se_ListCustomVerificationEmailTemplatesCommand).de(de_ListCustomVerificationEmailTemplatesCommand).build() {
  static {
    __name(this, "ListCustomVerificationEmailTemplatesCommand");
  }
};

// src/commands/ListDedicatedIpPoolsCommand.ts



var ListDedicatedIpPoolsCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "ListDedicatedIpPools", {}).n("SESv2Client", "ListDedicatedIpPoolsCommand").f(void 0, void 0).ser(se_ListDedicatedIpPoolsCommand).de(de_ListDedicatedIpPoolsCommand).build() {
  static {
    __name(this, "ListDedicatedIpPoolsCommand");
  }
};

// src/commands/ListDeliverabilityTestReportsCommand.ts



var ListDeliverabilityTestReportsCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "ListDeliverabilityTestReports", {}).n("SESv2Client", "ListDeliverabilityTestReportsCommand").f(void 0, void 0).ser(se_ListDeliverabilityTestReportsCommand).de(de_ListDeliverabilityTestReportsCommand).build() {
  static {
    __name(this, "ListDeliverabilityTestReportsCommand");
  }
};

// src/commands/ListDomainDeliverabilityCampaignsCommand.ts



var ListDomainDeliverabilityCampaignsCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "ListDomainDeliverabilityCampaigns", {}).n("SESv2Client", "ListDomainDeliverabilityCampaignsCommand").f(void 0, void 0).ser(se_ListDomainDeliverabilityCampaignsCommand).de(de_ListDomainDeliverabilityCampaignsCommand).build() {
  static {
    __name(this, "ListDomainDeliverabilityCampaignsCommand");
  }
};

// src/commands/ListEmailIdentitiesCommand.ts



var ListEmailIdentitiesCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "ListEmailIdentities", {}).n("SESv2Client", "ListEmailIdentitiesCommand").f(void 0, void 0).ser(se_ListEmailIdentitiesCommand).de(de_ListEmailIdentitiesCommand).build() {
  static {
    __name(this, "ListEmailIdentitiesCommand");
  }
};

// src/commands/ListEmailTemplatesCommand.ts



var ListEmailTemplatesCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "ListEmailTemplates", {}).n("SESv2Client", "ListEmailTemplatesCommand").f(void 0, void 0).ser(se_ListEmailTemplatesCommand).de(de_ListEmailTemplatesCommand).build() {
  static {
    __name(this, "ListEmailTemplatesCommand");
  }
};

// src/commands/ListExportJobsCommand.ts



var ListExportJobsCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "ListExportJobs", {}).n("SESv2Client", "ListExportJobsCommand").f(void 0, void 0).ser(se_ListExportJobsCommand).de(de_ListExportJobsCommand).build() {
  static {
    __name(this, "ListExportJobsCommand");
  }
};

// src/commands/ListImportJobsCommand.ts



var ListImportJobsCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "ListImportJobs", {}).n("SESv2Client", "ListImportJobsCommand").f(void 0, void 0).ser(se_ListImportJobsCommand).de(de_ListImportJobsCommand).build() {
  static {
    __name(this, "ListImportJobsCommand");
  }
};

// src/commands/ListMultiRegionEndpointsCommand.ts



var ListMultiRegionEndpointsCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "ListMultiRegionEndpoints", {}).n("SESv2Client", "ListMultiRegionEndpointsCommand").f(void 0, void 0).ser(se_ListMultiRegionEndpointsCommand).de(de_ListMultiRegionEndpointsCommand).build() {
  static {
    __name(this, "ListMultiRegionEndpointsCommand");
  }
};

// src/commands/ListRecommendationsCommand.ts



var ListRecommendationsCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "ListRecommendations", {}).n("SESv2Client", "ListRecommendationsCommand").f(void 0, void 0).ser(se_ListRecommendationsCommand).de(de_ListRecommendationsCommand).build() {
  static {
    __name(this, "ListRecommendationsCommand");
  }
};

// src/commands/ListReputationEntitiesCommand.ts



var ListReputationEntitiesCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "ListReputationEntities", {}).n("SESv2Client", "ListReputationEntitiesCommand").f(void 0, void 0).ser(se_ListReputationEntitiesCommand).de(de_ListReputationEntitiesCommand).build() {
  static {
    __name(this, "ListReputationEntitiesCommand");
  }
};

// src/commands/ListResourceTenantsCommand.ts



var ListResourceTenantsCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "ListResourceTenants", {}).n("SESv2Client", "ListResourceTenantsCommand").f(void 0, void 0).ser(se_ListResourceTenantsCommand).de(de_ListResourceTenantsCommand).build() {
  static {
    __name(this, "ListResourceTenantsCommand");
  }
};

// src/commands/ListSuppressedDestinationsCommand.ts



var ListSuppressedDestinationsCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "ListSuppressedDestinations", {}).n("SESv2Client", "ListSuppressedDestinationsCommand").f(void 0, void 0).ser(se_ListSuppressedDestinationsCommand).de(de_ListSuppressedDestinationsCommand).build() {
  static {
    __name(this, "ListSuppressedDestinationsCommand");
  }
};

// src/commands/ListTagsForResourceCommand.ts



var ListTagsForResourceCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "ListTagsForResource", {}).n("SESv2Client", "ListTagsForResourceCommand").f(void 0, void 0).ser(se_ListTagsForResourceCommand).de(de_ListTagsForResourceCommand).build() {
  static {
    __name(this, "ListTagsForResourceCommand");
  }
};

// src/commands/ListTenantResourcesCommand.ts



var ListTenantResourcesCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "ListTenantResources", {}).n("SESv2Client", "ListTenantResourcesCommand").f(void 0, void 0).ser(se_ListTenantResourcesCommand).de(de_ListTenantResourcesCommand).build() {
  static {
    __name(this, "ListTenantResourcesCommand");
  }
};

// src/commands/ListTenantsCommand.ts



var ListTenantsCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "ListTenants", {}).n("SESv2Client", "ListTenantsCommand").f(void 0, void 0).ser(se_ListTenantsCommand).de(de_ListTenantsCommand).build() {
  static {
    __name(this, "ListTenantsCommand");
  }
};

// src/commands/PutAccountDedicatedIpWarmupAttributesCommand.ts



var PutAccountDedicatedIpWarmupAttributesCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "PutAccountDedicatedIpWarmupAttributes", {}).n("SESv2Client", "PutAccountDedicatedIpWarmupAttributesCommand").f(void 0, void 0).ser(se_PutAccountDedicatedIpWarmupAttributesCommand).de(de_PutAccountDedicatedIpWarmupAttributesCommand).build() {
  static {
    __name(this, "PutAccountDedicatedIpWarmupAttributesCommand");
  }
};

// src/commands/PutAccountDetailsCommand.ts




// src/models/models_1.ts

var ListTenantResourcesFilterKey = {
  RESOURCE_TYPE: "RESOURCE_TYPE"
};
var ResourceType = {
  CONFIGURATION_SET: "CONFIGURATION_SET",
  EMAIL_IDENTITY: "EMAIL_IDENTITY",
  EMAIL_TEMPLATE: "EMAIL_TEMPLATE"
};
var PutAccountDetailsRequestFilterSensitiveLog = /* @__PURE__ */ __name((obj) => ({
  ...obj,
  ...obj.WebsiteURL && { WebsiteURL: import_smithy_client.SENSITIVE_STRING },
  ...obj.UseCaseDescription && { UseCaseDescription: import_smithy_client.SENSITIVE_STRING },
  ...obj.AdditionalContactEmailAddresses && { AdditionalContactEmailAddresses: import_smithy_client.SENSITIVE_STRING }
}), "PutAccountDetailsRequestFilterSensitiveLog");
var PutEmailIdentityDkimSigningAttributesRequestFilterSensitiveLog = /* @__PURE__ */ __name((obj) => ({
  ...obj,
  ...obj.SigningAttributes && { SigningAttributes: DkimSigningAttributesFilterSensitiveLog(obj.SigningAttributes) }
}), "PutEmailIdentityDkimSigningAttributesRequestFilterSensitiveLog");

// src/commands/PutAccountDetailsCommand.ts
var PutAccountDetailsCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "PutAccountDetails", {}).n("SESv2Client", "PutAccountDetailsCommand").f(PutAccountDetailsRequestFilterSensitiveLog, void 0).ser(se_PutAccountDetailsCommand).de(de_PutAccountDetailsCommand).build() {
  static {
    __name(this, "PutAccountDetailsCommand");
  }
};

// src/commands/PutAccountSendingAttributesCommand.ts



var PutAccountSendingAttributesCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "PutAccountSendingAttributes", {}).n("SESv2Client", "PutAccountSendingAttributesCommand").f(void 0, void 0).ser(se_PutAccountSendingAttributesCommand).de(de_PutAccountSendingAttributesCommand).build() {
  static {
    __name(this, "PutAccountSendingAttributesCommand");
  }
};

// src/commands/PutAccountSuppressionAttributesCommand.ts



var PutAccountSuppressionAttributesCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "PutAccountSuppressionAttributes", {}).n("SESv2Client", "PutAccountSuppressionAttributesCommand").f(void 0, void 0).ser(se_PutAccountSuppressionAttributesCommand).de(de_PutAccountSuppressionAttributesCommand).build() {
  static {
    __name(this, "PutAccountSuppressionAttributesCommand");
  }
};

// src/commands/PutAccountVdmAttributesCommand.ts



var PutAccountVdmAttributesCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "PutAccountVdmAttributes", {}).n("SESv2Client", "PutAccountVdmAttributesCommand").f(void 0, void 0).ser(se_PutAccountVdmAttributesCommand).de(de_PutAccountVdmAttributesCommand).build() {
  static {
    __name(this, "PutAccountVdmAttributesCommand");
  }
};

// src/commands/PutConfigurationSetArchivingOptionsCommand.ts



var PutConfigurationSetArchivingOptionsCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "PutConfigurationSetArchivingOptions", {}).n("SESv2Client", "PutConfigurationSetArchivingOptionsCommand").f(void 0, void 0).ser(se_PutConfigurationSetArchivingOptionsCommand).de(de_PutConfigurationSetArchivingOptionsCommand).build() {
  static {
    __name(this, "PutConfigurationSetArchivingOptionsCommand");
  }
};

// src/commands/PutConfigurationSetDeliveryOptionsCommand.ts



var PutConfigurationSetDeliveryOptionsCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "PutConfigurationSetDeliveryOptions", {}).n("SESv2Client", "PutConfigurationSetDeliveryOptionsCommand").f(void 0, void 0).ser(se_PutConfigurationSetDeliveryOptionsCommand).de(de_PutConfigurationSetDeliveryOptionsCommand).build() {
  static {
    __name(this, "PutConfigurationSetDeliveryOptionsCommand");
  }
};

// src/commands/PutConfigurationSetReputationOptionsCommand.ts



var PutConfigurationSetReputationOptionsCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "PutConfigurationSetReputationOptions", {}).n("SESv2Client", "PutConfigurationSetReputationOptionsCommand").f(void 0, void 0).ser(se_PutConfigurationSetReputationOptionsCommand).de(de_PutConfigurationSetReputationOptionsCommand).build() {
  static {
    __name(this, "PutConfigurationSetReputationOptionsCommand");
  }
};

// src/commands/PutConfigurationSetSendingOptionsCommand.ts



var PutConfigurationSetSendingOptionsCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "PutConfigurationSetSendingOptions", {}).n("SESv2Client", "PutConfigurationSetSendingOptionsCommand").f(void 0, void 0).ser(se_PutConfigurationSetSendingOptionsCommand).de(de_PutConfigurationSetSendingOptionsCommand).build() {
  static {
    __name(this, "PutConfigurationSetSendingOptionsCommand");
  }
};

// src/commands/PutConfigurationSetSuppressionOptionsCommand.ts



var PutConfigurationSetSuppressionOptionsCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "PutConfigurationSetSuppressionOptions", {}).n("SESv2Client", "PutConfigurationSetSuppressionOptionsCommand").f(void 0, void 0).ser(se_PutConfigurationSetSuppressionOptionsCommand).de(de_PutConfigurationSetSuppressionOptionsCommand).build() {
  static {
    __name(this, "PutConfigurationSetSuppressionOptionsCommand");
  }
};

// src/commands/PutConfigurationSetTrackingOptionsCommand.ts



var PutConfigurationSetTrackingOptionsCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "PutConfigurationSetTrackingOptions", {}).n("SESv2Client", "PutConfigurationSetTrackingOptionsCommand").f(void 0, void 0).ser(se_PutConfigurationSetTrackingOptionsCommand).de(de_PutConfigurationSetTrackingOptionsCommand).build() {
  static {
    __name(this, "PutConfigurationSetTrackingOptionsCommand");
  }
};

// src/commands/PutConfigurationSetVdmOptionsCommand.ts



var PutConfigurationSetVdmOptionsCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "PutConfigurationSetVdmOptions", {}).n("SESv2Client", "PutConfigurationSetVdmOptionsCommand").f(void 0, void 0).ser(se_PutConfigurationSetVdmOptionsCommand).de(de_PutConfigurationSetVdmOptionsCommand).build() {
  static {
    __name(this, "PutConfigurationSetVdmOptionsCommand");
  }
};

// src/commands/PutDedicatedIpInPoolCommand.ts



var PutDedicatedIpInPoolCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "PutDedicatedIpInPool", {}).n("SESv2Client", "PutDedicatedIpInPoolCommand").f(void 0, void 0).ser(se_PutDedicatedIpInPoolCommand).de(de_PutDedicatedIpInPoolCommand).build() {
  static {
    __name(this, "PutDedicatedIpInPoolCommand");
  }
};

// src/commands/PutDedicatedIpPoolScalingAttributesCommand.ts



var PutDedicatedIpPoolScalingAttributesCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "PutDedicatedIpPoolScalingAttributes", {}).n("SESv2Client", "PutDedicatedIpPoolScalingAttributesCommand").f(void 0, void 0).ser(se_PutDedicatedIpPoolScalingAttributesCommand).de(de_PutDedicatedIpPoolScalingAttributesCommand).build() {
  static {
    __name(this, "PutDedicatedIpPoolScalingAttributesCommand");
  }
};

// src/commands/PutDedicatedIpWarmupAttributesCommand.ts



var PutDedicatedIpWarmupAttributesCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "PutDedicatedIpWarmupAttributes", {}).n("SESv2Client", "PutDedicatedIpWarmupAttributesCommand").f(void 0, void 0).ser(se_PutDedicatedIpWarmupAttributesCommand).de(de_PutDedicatedIpWarmupAttributesCommand).build() {
  static {
    __name(this, "PutDedicatedIpWarmupAttributesCommand");
  }
};

// src/commands/PutDeliverabilityDashboardOptionCommand.ts



var PutDeliverabilityDashboardOptionCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "PutDeliverabilityDashboardOption", {}).n("SESv2Client", "PutDeliverabilityDashboardOptionCommand").f(void 0, void 0).ser(se_PutDeliverabilityDashboardOptionCommand).de(de_PutDeliverabilityDashboardOptionCommand).build() {
  static {
    __name(this, "PutDeliverabilityDashboardOptionCommand");
  }
};

// src/commands/PutEmailIdentityConfigurationSetAttributesCommand.ts



var PutEmailIdentityConfigurationSetAttributesCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "PutEmailIdentityConfigurationSetAttributes", {}).n("SESv2Client", "PutEmailIdentityConfigurationSetAttributesCommand").f(void 0, void 0).ser(se_PutEmailIdentityConfigurationSetAttributesCommand).de(de_PutEmailIdentityConfigurationSetAttributesCommand).build() {
  static {
    __name(this, "PutEmailIdentityConfigurationSetAttributesCommand");
  }
};

// src/commands/PutEmailIdentityDkimAttributesCommand.ts



var PutEmailIdentityDkimAttributesCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "PutEmailIdentityDkimAttributes", {}).n("SESv2Client", "PutEmailIdentityDkimAttributesCommand").f(void 0, void 0).ser(se_PutEmailIdentityDkimAttributesCommand).de(de_PutEmailIdentityDkimAttributesCommand).build() {
  static {
    __name(this, "PutEmailIdentityDkimAttributesCommand");
  }
};

// src/commands/PutEmailIdentityDkimSigningAttributesCommand.ts



var PutEmailIdentityDkimSigningAttributesCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "PutEmailIdentityDkimSigningAttributes", {}).n("SESv2Client", "PutEmailIdentityDkimSigningAttributesCommand").f(PutEmailIdentityDkimSigningAttributesRequestFilterSensitiveLog, void 0).ser(se_PutEmailIdentityDkimSigningAttributesCommand).de(de_PutEmailIdentityDkimSigningAttributesCommand).build() {
  static {
    __name(this, "PutEmailIdentityDkimSigningAttributesCommand");
  }
};

// src/commands/PutEmailIdentityFeedbackAttributesCommand.ts



var PutEmailIdentityFeedbackAttributesCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "PutEmailIdentityFeedbackAttributes", {}).n("SESv2Client", "PutEmailIdentityFeedbackAttributesCommand").f(void 0, void 0).ser(se_PutEmailIdentityFeedbackAttributesCommand).de(de_PutEmailIdentityFeedbackAttributesCommand).build() {
  static {
    __name(this, "PutEmailIdentityFeedbackAttributesCommand");
  }
};

// src/commands/PutEmailIdentityMailFromAttributesCommand.ts



var PutEmailIdentityMailFromAttributesCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "PutEmailIdentityMailFromAttributes", {}).n("SESv2Client", "PutEmailIdentityMailFromAttributesCommand").f(void 0, void 0).ser(se_PutEmailIdentityMailFromAttributesCommand).de(de_PutEmailIdentityMailFromAttributesCommand).build() {
  static {
    __name(this, "PutEmailIdentityMailFromAttributesCommand");
  }
};

// src/commands/PutSuppressedDestinationCommand.ts



var PutSuppressedDestinationCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "PutSuppressedDestination", {}).n("SESv2Client", "PutSuppressedDestinationCommand").f(void 0, void 0).ser(se_PutSuppressedDestinationCommand).de(de_PutSuppressedDestinationCommand).build() {
  static {
    __name(this, "PutSuppressedDestinationCommand");
  }
};

// src/commands/SendBulkEmailCommand.ts



var SendBulkEmailCommand = class extends import_smithy_client.Command.classBuilder().ep({
  ...commonParams,
  EndpointId: { type: "contextParams", name: "EndpointId" }
}).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "SendBulkEmail", {}).n("SESv2Client", "SendBulkEmailCommand").f(void 0, void 0).ser(se_SendBulkEmailCommand).de(de_SendBulkEmailCommand).build() {
  static {
    __name(this, "SendBulkEmailCommand");
  }
};

// src/commands/SendCustomVerificationEmailCommand.ts



var SendCustomVerificationEmailCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "SendCustomVerificationEmail", {}).n("SESv2Client", "SendCustomVerificationEmailCommand").f(void 0, void 0).ser(se_SendCustomVerificationEmailCommand).de(de_SendCustomVerificationEmailCommand).build() {
  static {
    __name(this, "SendCustomVerificationEmailCommand");
  }
};

// src/commands/SendEmailCommand.ts



var SendEmailCommand = class extends import_smithy_client.Command.classBuilder().ep({
  ...commonParams,
  EndpointId: { type: "contextParams", name: "EndpointId" }
}).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "SendEmail", {}).n("SESv2Client", "SendEmailCommand").f(void 0, void 0).ser(se_SendEmailCommand).de(de_SendEmailCommand).build() {
  static {
    __name(this, "SendEmailCommand");
  }
};

// src/commands/TagResourceCommand.ts



var TagResourceCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "TagResource", {}).n("SESv2Client", "TagResourceCommand").f(void 0, void 0).ser(se_TagResourceCommand).de(de_TagResourceCommand).build() {
  static {
    __name(this, "TagResourceCommand");
  }
};

// src/commands/TestRenderEmailTemplateCommand.ts



var TestRenderEmailTemplateCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "TestRenderEmailTemplate", {}).n("SESv2Client", "TestRenderEmailTemplateCommand").f(void 0, void 0).ser(se_TestRenderEmailTemplateCommand).de(de_TestRenderEmailTemplateCommand).build() {
  static {
    __name(this, "TestRenderEmailTemplateCommand");
  }
};

// src/commands/UntagResourceCommand.ts



var UntagResourceCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "UntagResource", {}).n("SESv2Client", "UntagResourceCommand").f(void 0, void 0).ser(se_UntagResourceCommand).de(de_UntagResourceCommand).build() {
  static {
    __name(this, "UntagResourceCommand");
  }
};

// src/commands/UpdateConfigurationSetEventDestinationCommand.ts



var UpdateConfigurationSetEventDestinationCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "UpdateConfigurationSetEventDestination", {}).n("SESv2Client", "UpdateConfigurationSetEventDestinationCommand").f(void 0, void 0).ser(se_UpdateConfigurationSetEventDestinationCommand).de(de_UpdateConfigurationSetEventDestinationCommand).build() {
  static {
    __name(this, "UpdateConfigurationSetEventDestinationCommand");
  }
};

// src/commands/UpdateContactCommand.ts



var UpdateContactCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "UpdateContact", {}).n("SESv2Client", "UpdateContactCommand").f(void 0, void 0).ser(se_UpdateContactCommand).de(de_UpdateContactCommand).build() {
  static {
    __name(this, "UpdateContactCommand");
  }
};

// src/commands/UpdateContactListCommand.ts



var UpdateContactListCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "UpdateContactList", {}).n("SESv2Client", "UpdateContactListCommand").f(void 0, void 0).ser(se_UpdateContactListCommand).de(de_UpdateContactListCommand).build() {
  static {
    __name(this, "UpdateContactListCommand");
  }
};

// src/commands/UpdateCustomVerificationEmailTemplateCommand.ts



var UpdateCustomVerificationEmailTemplateCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "UpdateCustomVerificationEmailTemplate", {}).n("SESv2Client", "UpdateCustomVerificationEmailTemplateCommand").f(void 0, void 0).ser(se_UpdateCustomVerificationEmailTemplateCommand).de(de_UpdateCustomVerificationEmailTemplateCommand).build() {
  static {
    __name(this, "UpdateCustomVerificationEmailTemplateCommand");
  }
};

// src/commands/UpdateEmailIdentityPolicyCommand.ts



var UpdateEmailIdentityPolicyCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "UpdateEmailIdentityPolicy", {}).n("SESv2Client", "UpdateEmailIdentityPolicyCommand").f(void 0, void 0).ser(se_UpdateEmailIdentityPolicyCommand).de(de_UpdateEmailIdentityPolicyCommand).build() {
  static {
    __name(this, "UpdateEmailIdentityPolicyCommand");
  }
};

// src/commands/UpdateEmailTemplateCommand.ts



var UpdateEmailTemplateCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "UpdateEmailTemplate", {}).n("SESv2Client", "UpdateEmailTemplateCommand").f(void 0, void 0).ser(se_UpdateEmailTemplateCommand).de(de_UpdateEmailTemplateCommand).build() {
  static {
    __name(this, "UpdateEmailTemplateCommand");
  }
};

// src/commands/UpdateReputationEntityCustomerManagedStatusCommand.ts



var UpdateReputationEntityCustomerManagedStatusCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "UpdateReputationEntityCustomerManagedStatus", {}).n("SESv2Client", "UpdateReputationEntityCustomerManagedStatusCommand").f(void 0, void 0).ser(se_UpdateReputationEntityCustomerManagedStatusCommand).de(de_UpdateReputationEntityCustomerManagedStatusCommand).build() {
  static {
    __name(this, "UpdateReputationEntityCustomerManagedStatusCommand");
  }
};

// src/commands/UpdateReputationEntityPolicyCommand.ts



var UpdateReputationEntityPolicyCommand = class extends import_smithy_client.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SimpleEmailService_v2", "UpdateReputationEntityPolicy", {}).n("SESv2Client", "UpdateReputationEntityPolicyCommand").f(void 0, void 0).ser(se_UpdateReputationEntityPolicyCommand).de(de_UpdateReputationEntityPolicyCommand).build() {
  static {
    __name(this, "UpdateReputationEntityPolicyCommand");
  }
};

// src/SESv2.ts
var commands = {
  BatchGetMetricDataCommand,
  CancelExportJobCommand,
  CreateConfigurationSetCommand,
  CreateConfigurationSetEventDestinationCommand,
  CreateContactCommand,
  CreateContactListCommand,
  CreateCustomVerificationEmailTemplateCommand,
  CreateDedicatedIpPoolCommand,
  CreateDeliverabilityTestReportCommand,
  CreateEmailIdentityCommand,
  CreateEmailIdentityPolicyCommand,
  CreateEmailTemplateCommand,
  CreateExportJobCommand,
  CreateImportJobCommand,
  CreateMultiRegionEndpointCommand,
  CreateTenantCommand,
  CreateTenantResourceAssociationCommand,
  DeleteConfigurationSetCommand,
  DeleteConfigurationSetEventDestinationCommand,
  DeleteContactCommand,
  DeleteContactListCommand,
  DeleteCustomVerificationEmailTemplateCommand,
  DeleteDedicatedIpPoolCommand,
  DeleteEmailIdentityCommand,
  DeleteEmailIdentityPolicyCommand,
  DeleteEmailTemplateCommand,
  DeleteMultiRegionEndpointCommand,
  DeleteSuppressedDestinationCommand,
  DeleteTenantCommand,
  DeleteTenantResourceAssociationCommand,
  GetAccountCommand,
  GetBlacklistReportsCommand,
  GetConfigurationSetCommand,
  GetConfigurationSetEventDestinationsCommand,
  GetContactCommand,
  GetContactListCommand,
  GetCustomVerificationEmailTemplateCommand,
  GetDedicatedIpCommand,
  GetDedicatedIpPoolCommand,
  GetDedicatedIpsCommand,
  GetDeliverabilityDashboardOptionsCommand,
  GetDeliverabilityTestReportCommand,
  GetDomainDeliverabilityCampaignCommand,
  GetDomainStatisticsReportCommand,
  GetEmailIdentityCommand,
  GetEmailIdentityPoliciesCommand,
  GetEmailTemplateCommand,
  GetExportJobCommand,
  GetImportJobCommand,
  GetMessageInsightsCommand,
  GetMultiRegionEndpointCommand,
  GetReputationEntityCommand,
  GetSuppressedDestinationCommand,
  GetTenantCommand,
  ListConfigurationSetsCommand,
  ListContactListsCommand,
  ListContactsCommand,
  ListCustomVerificationEmailTemplatesCommand,
  ListDedicatedIpPoolsCommand,
  ListDeliverabilityTestReportsCommand,
  ListDomainDeliverabilityCampaignsCommand,
  ListEmailIdentitiesCommand,
  ListEmailTemplatesCommand,
  ListExportJobsCommand,
  ListImportJobsCommand,
  ListMultiRegionEndpointsCommand,
  ListRecommendationsCommand,
  ListReputationEntitiesCommand,
  ListResourceTenantsCommand,
  ListSuppressedDestinationsCommand,
  ListTagsForResourceCommand,
  ListTenantResourcesCommand,
  ListTenantsCommand,
  PutAccountDedicatedIpWarmupAttributesCommand,
  PutAccountDetailsCommand,
  PutAccountSendingAttributesCommand,
  PutAccountSuppressionAttributesCommand,
  PutAccountVdmAttributesCommand,
  PutConfigurationSetArchivingOptionsCommand,
  PutConfigurationSetDeliveryOptionsCommand,
  PutConfigurationSetReputationOptionsCommand,
  PutConfigurationSetSendingOptionsCommand,
  PutConfigurationSetSuppressionOptionsCommand,
  PutConfigurationSetTrackingOptionsCommand,
  PutConfigurationSetVdmOptionsCommand,
  PutDedicatedIpInPoolCommand,
  PutDedicatedIpPoolScalingAttributesCommand,
  PutDedicatedIpWarmupAttributesCommand,
  PutDeliverabilityDashboardOptionCommand,
  PutEmailIdentityConfigurationSetAttributesCommand,
  PutEmailIdentityDkimAttributesCommand,
  PutEmailIdentityDkimSigningAttributesCommand,
  PutEmailIdentityFeedbackAttributesCommand,
  PutEmailIdentityMailFromAttributesCommand,
  PutSuppressedDestinationCommand,
  SendBulkEmailCommand,
  SendCustomVerificationEmailCommand,
  SendEmailCommand,
  TagResourceCommand,
  TestRenderEmailTemplateCommand,
  UntagResourceCommand,
  UpdateConfigurationSetEventDestinationCommand,
  UpdateContactCommand,
  UpdateContactListCommand,
  UpdateCustomVerificationEmailTemplateCommand,
  UpdateEmailIdentityPolicyCommand,
  UpdateEmailTemplateCommand,
  UpdateReputationEntityCustomerManagedStatusCommand,
  UpdateReputationEntityPolicyCommand
};
var SESv2 = class extends SESv2Client {
  static {
    __name(this, "SESv2");
  }
};
(0, import_smithy_client.createAggregatedClient)(commands, SESv2);

// src/pagination/GetDedicatedIpsPaginator.ts

var paginateGetDedicatedIps = (0, import_core.createPaginator)(SESv2Client, GetDedicatedIpsCommand, "NextToken", "NextToken", "PageSize");

// src/pagination/ListConfigurationSetsPaginator.ts

var paginateListConfigurationSets = (0, import_core.createPaginator)(SESv2Client, ListConfigurationSetsCommand, "NextToken", "NextToken", "PageSize");

// src/pagination/ListContactListsPaginator.ts

var paginateListContactLists = (0, import_core.createPaginator)(SESv2Client, ListContactListsCommand, "NextToken", "NextToken", "PageSize");

// src/pagination/ListContactsPaginator.ts

var paginateListContacts = (0, import_core.createPaginator)(SESv2Client, ListContactsCommand, "NextToken", "NextToken", "PageSize");

// src/pagination/ListCustomVerificationEmailTemplatesPaginator.ts

var paginateListCustomVerificationEmailTemplates = (0, import_core.createPaginator)(SESv2Client, ListCustomVerificationEmailTemplatesCommand, "NextToken", "NextToken", "PageSize");

// src/pagination/ListDedicatedIpPoolsPaginator.ts

var paginateListDedicatedIpPools = (0, import_core.createPaginator)(SESv2Client, ListDedicatedIpPoolsCommand, "NextToken", "NextToken", "PageSize");

// src/pagination/ListDeliverabilityTestReportsPaginator.ts

var paginateListDeliverabilityTestReports = (0, import_core.createPaginator)(SESv2Client, ListDeliverabilityTestReportsCommand, "NextToken", "NextToken", "PageSize");

// src/pagination/ListDomainDeliverabilityCampaignsPaginator.ts

var paginateListDomainDeliverabilityCampaigns = (0, import_core.createPaginator)(SESv2Client, ListDomainDeliverabilityCampaignsCommand, "NextToken", "NextToken", "PageSize");

// src/pagination/ListEmailIdentitiesPaginator.ts

var paginateListEmailIdentities = (0, import_core.createPaginator)(SESv2Client, ListEmailIdentitiesCommand, "NextToken", "NextToken", "PageSize");

// src/pagination/ListEmailTemplatesPaginator.ts

var paginateListEmailTemplates = (0, import_core.createPaginator)(SESv2Client, ListEmailTemplatesCommand, "NextToken", "NextToken", "PageSize");

// src/pagination/ListExportJobsPaginator.ts

var paginateListExportJobs = (0, import_core.createPaginator)(SESv2Client, ListExportJobsCommand, "NextToken", "NextToken", "PageSize");

// src/pagination/ListImportJobsPaginator.ts

var paginateListImportJobs = (0, import_core.createPaginator)(SESv2Client, ListImportJobsCommand, "NextToken", "NextToken", "PageSize");

// src/pagination/ListMultiRegionEndpointsPaginator.ts

var paginateListMultiRegionEndpoints = (0, import_core.createPaginator)(SESv2Client, ListMultiRegionEndpointsCommand, "NextToken", "NextToken", "PageSize");

// src/pagination/ListRecommendationsPaginator.ts

var paginateListRecommendations = (0, import_core.createPaginator)(SESv2Client, ListRecommendationsCommand, "NextToken", "NextToken", "PageSize");

// src/pagination/ListReputationEntitiesPaginator.ts

var paginateListReputationEntities = (0, import_core.createPaginator)(SESv2Client, ListReputationEntitiesCommand, "NextToken", "NextToken", "PageSize");

// src/pagination/ListResourceTenantsPaginator.ts

var paginateListResourceTenants = (0, import_core.createPaginator)(SESv2Client, ListResourceTenantsCommand, "NextToken", "NextToken", "PageSize");

// src/pagination/ListSuppressedDestinationsPaginator.ts

var paginateListSuppressedDestinations = (0, import_core.createPaginator)(SESv2Client, ListSuppressedDestinationsCommand, "NextToken", "NextToken", "PageSize");

// src/pagination/ListTenantResourcesPaginator.ts

var paginateListTenantResources = (0, import_core.createPaginator)(SESv2Client, ListTenantResourcesCommand, "NextToken", "NextToken", "PageSize");

// src/pagination/ListTenantsPaginator.ts

var paginateListTenants = (0, import_core.createPaginator)(SESv2Client, ListTenantsCommand, "NextToken", "NextToken", "PageSize");
// Annotate the CommonJS export names for ESM import in node:

0 && (module.exports = {
  SESv2ServiceException,
  __Client,
  SESv2Client,
  SESv2,
  $Command,
  BatchGetMetricDataCommand,
  CancelExportJobCommand,
  CreateConfigurationSetCommand,
  CreateConfigurationSetEventDestinationCommand,
  CreateContactCommand,
  CreateContactListCommand,
  CreateCustomVerificationEmailTemplateCommand,
  CreateDedicatedIpPoolCommand,
  CreateDeliverabilityTestReportCommand,
  CreateEmailIdentityCommand,
  CreateEmailIdentityPolicyCommand,
  CreateEmailTemplateCommand,
  CreateExportJobCommand,
  CreateImportJobCommand,
  CreateMultiRegionEndpointCommand,
  CreateTenantCommand,
  CreateTenantResourceAssociationCommand,
  DeleteConfigurationSetCommand,
  DeleteConfigurationSetEventDestinationCommand,
  DeleteContactCommand,
  DeleteContactListCommand,
  DeleteCustomVerificationEmailTemplateCommand,
  DeleteDedicatedIpPoolCommand,
  DeleteEmailIdentityCommand,
  DeleteEmailIdentityPolicyCommand,
  DeleteEmailTemplateCommand,
  DeleteMultiRegionEndpointCommand,
  DeleteSuppressedDestinationCommand,
  DeleteTenantCommand,
  DeleteTenantResourceAssociationCommand,
  GetAccountCommand,
  GetBlacklistReportsCommand,
  GetConfigurationSetCommand,
  GetConfigurationSetEventDestinationsCommand,
  GetContactCommand,
  GetContactListCommand,
  GetCustomVerificationEmailTemplateCommand,
  GetDedicatedIpCommand,
  GetDedicatedIpPoolCommand,
  GetDedicatedIpsCommand,
  GetDeliverabilityDashboardOptionsCommand,
  GetDeliverabilityTestReportCommand,
  GetDomainDeliverabilityCampaignCommand,
  GetDomainStatisticsReportCommand,
  GetEmailIdentityCommand,
  GetEmailIdentityPoliciesCommand,
  GetEmailTemplateCommand,
  GetExportJobCommand,
  GetImportJobCommand,
  GetMessageInsightsCommand,
  GetMultiRegionEndpointCommand,
  GetReputationEntityCommand,
  GetSuppressedDestinationCommand,
  GetTenantCommand,
  ListConfigurationSetsCommand,
  ListContactListsCommand,
  ListContactsCommand,
  ListCustomVerificationEmailTemplatesCommand,
  ListDedicatedIpPoolsCommand,
  ListDeliverabilityTestReportsCommand,
  ListDomainDeliverabilityCampaignsCommand,
  ListEmailIdentitiesCommand,
  ListEmailTemplatesCommand,
  ListExportJobsCommand,
  ListImportJobsCommand,
  ListMultiRegionEndpointsCommand,
  ListRecommendationsCommand,
  ListReputationEntitiesCommand,
  ListResourceTenantsCommand,
  ListSuppressedDestinationsCommand,
  ListTagsForResourceCommand,
  ListTenantResourcesCommand,
  ListTenantsCommand,
  PutAccountDedicatedIpWarmupAttributesCommand,
  PutAccountDetailsCommand,
  PutAccountSendingAttributesCommand,
  PutAccountSuppressionAttributesCommand,
  PutAccountVdmAttributesCommand,
  PutConfigurationSetArchivingOptionsCommand,
  PutConfigurationSetDeliveryOptionsCommand,
  PutConfigurationSetReputationOptionsCommand,
  PutConfigurationSetSendingOptionsCommand,
  PutConfigurationSetSuppressionOptionsCommand,
  PutConfigurationSetTrackingOptionsCommand,
  PutConfigurationSetVdmOptionsCommand,
  PutDedicatedIpInPoolCommand,
  PutDedicatedIpPoolScalingAttributesCommand,
  PutDedicatedIpWarmupAttributesCommand,
  PutDeliverabilityDashboardOptionCommand,
  PutEmailIdentityConfigurationSetAttributesCommand,
  PutEmailIdentityDkimAttributesCommand,
  PutEmailIdentityDkimSigningAttributesCommand,
  PutEmailIdentityFeedbackAttributesCommand,
  PutEmailIdentityMailFromAttributesCommand,
  PutSuppressedDestinationCommand,
  SendBulkEmailCommand,
  SendCustomVerificationEmailCommand,
  SendEmailCommand,
  TagResourceCommand,
  TestRenderEmailTemplateCommand,
  UntagResourceCommand,
  UpdateConfigurationSetEventDestinationCommand,
  UpdateContactCommand,
  UpdateContactListCommand,
  UpdateCustomVerificationEmailTemplateCommand,
  UpdateEmailIdentityPolicyCommand,
  UpdateEmailTemplateCommand,
  UpdateReputationEntityCustomerManagedStatusCommand,
  UpdateReputationEntityPolicyCommand,
  paginateGetDedicatedIps,
  paginateListConfigurationSets,
  paginateListContactLists,
  paginateListContacts,
  paginateListCustomVerificationEmailTemplates,
  paginateListDedicatedIpPools,
  paginateListDeliverabilityTestReports,
  paginateListDomainDeliverabilityCampaigns,
  paginateListEmailIdentities,
  paginateListEmailTemplates,
  paginateListExportJobs,
  paginateListImportJobs,
  paginateListMultiRegionEndpoints,
  paginateListRecommendations,
  paginateListReputationEntities,
  paginateListResourceTenants,
  paginateListSuppressedDestinations,
  paginateListTenantResources,
  paginateListTenants,
  ContactLanguage,
  MailType,
  ReviewStatus,
  AccountSuspendedException,
  AlreadyExistsException,
  AttachmentContentDisposition,
  AttachmentContentTransferEncoding,
  BadRequestException,
  MetricDimensionName,
  Metric,
  MetricNamespace,
  QueryErrorCode,
  InternalServiceErrorException,
  NotFoundException,
  TooManyRequestsException,
  BehaviorOnMxFailure,
  BounceType,
  BulkEmailStatus,
  DimensionValueSource,
  ConcurrentModificationException,
  ConflictException,
  SubscriptionStatus,
  ContactListImportAction,
  TlsPolicy,
  SuppressionListReason,
  HttpsPolicy,
  FeatureStatus,
  LimitExceededException,
  EventType,
  ScalingMode,
  DeliverabilityTestStatus,
  MailFromDomainNotVerifiedException,
  MessageRejected,
  SendingPausedException,
  DkimSigningAttributesOrigin,
  DkimSigningKeyLength,
  DkimStatus,
  IdentityType,
  DeliveryEventType,
  EngagementEventType,
  MetricAggregation,
  DataFormat,
  SuppressionListImportAction,
  Status,
  SendingStatus,
  WarmupStatus,
  DeliverabilityDashboardAccountStatus,
  ExportSourceType,
  JobStatus,
  MailFromDomainStatus,
  VerificationError,
  VerificationStatus,
  ReputationEntityType,
  RecommendationImpact,
  ImportDestinationType,
  InvalidNextTokenException,
  ListRecommendationsFilterKey,
  RecommendationStatus,
  RecommendationType,
  ReputationEntityFilterKey,
  AccountDetailsFilterSensitiveLog,
  DkimSigningAttributesFilterSensitiveLog,
  CreateEmailIdentityRequestFilterSensitiveLog,
  MessageInsightsFiltersFilterSensitiveLog,
  MessageInsightsDataSourceFilterSensitiveLog,
  ExportDataSourceFilterSensitiveLog,
  CreateExportJobRequestFilterSensitiveLog,
  EmailInsightsFilterSensitiveLog,
  GetAccountResponseFilterSensitiveLog,
  GetExportJobResponseFilterSensitiveLog,
  GetMessageInsightsResponseFilterSensitiveLog,
  ListTenantResourcesFilterKey,
  ResourceType,
  PutAccountDetailsRequestFilterSensitiveLog,
  PutEmailIdentityDkimSigningAttributesRequestFilterSensitiveLog
});

