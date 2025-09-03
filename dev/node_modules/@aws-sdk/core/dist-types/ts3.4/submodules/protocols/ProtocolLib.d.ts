import {
  ErrorSchema,
  NormalizedSchema,
  TypeRegistry,
} from "@smithy/core/schema";
import {
  HttpResponse as IHttpResponse,
  MetadataBearer,
  ResponseMetadata,
  SerdeFunctions,
} from "@smithy/types";
type ErrorMetadataBearer = MetadataBearer & {
  $response: IHttpResponse;
  $fault: "client" | "server";
};
export declare class ProtocolLib {
  calculateContentLength(body: any, serdeContext?: SerdeFunctions): string;
  resolveRestContentType(
    defaultContentType: string,
    inputSchema: NormalizedSchema
  ): string | undefined;
  getErrorSchemaOrThrowBaseException(
    errorIdentifier: string,
    defaultNamespace: string,
    response: IHttpResponse,
    dataObject: any,
    metadata: ResponseMetadata,
    getErrorSchema?: (registry: TypeRegistry, errorName: string) => ErrorSchema
  ): Promise<{
    errorSchema: ErrorSchema;
    errorMetadata: ErrorMetadataBearer;
  }>;
  setQueryCompatError(
    output: Record<string, any>,
    response: IHttpResponse
  ): void;
  queryCompatOutput(queryCompatErrorData: any, errorData: any): void;
}
export {};
