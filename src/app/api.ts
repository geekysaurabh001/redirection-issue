import axios from "axios";
import { setupInterceptors } from "./api-interceptor";

const axiosInstance = axios.create();
setupInterceptors(axiosInstance);

export default axiosInstance;
