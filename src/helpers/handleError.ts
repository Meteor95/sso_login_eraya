const isJSON = (message: string): boolean => {
    const trimmed = message.trim();
    return (trimmed.startsWith("{") && trimmed.endsWith("}")) || 
           (trimmed.startsWith("[") && trimmed.endsWith("]"));
};
export const handleError = (error: any, message = "Something went wrong.") => {
    return {
      status: 500,
      body: {
        success: false,
        message,
        error_messages: isJSON(error.message) ? JSON.parse(error.message) : error.message,
      }
    }
  }

