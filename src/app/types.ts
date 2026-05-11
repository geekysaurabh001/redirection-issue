type SuccessResponse<T> = {
  data: T;
  error: null;
};
type ErrorResponse = {
  error: string;
  data: null;
};
export type DataResponse<T> = SuccessResponse<T> | ErrorResponse;
