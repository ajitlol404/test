package com.comviva.mfs.sync.swagger.userManagement.api;

import com.comviva.mfs.common.util.Constants;
import com.comviva.mfs.common.util.MFSConfiguration;
import com.comviva.mfs.common.util.TenantUtil;
import com.comviva.mfs.sync.dto.TxnWebAppDTO;
import com.comviva.mfs.sync.enums.ServiceFlowIds;
import com.comviva.mfs.sync.handler.TxnWebApphandler;
import com.comviva.mfs.sync.helper.TxnConstants;
import com.comviva.mfs.sync.helper.TxnWebAppHelper;
import com.comviva.mfs.sync.service.BlacklistSessionsService;
import com.comviva.mfs.sync.swagger.userManagement.models.*;
import com.comviva.mfs.sync.swagger.userManagement.service.UserManagementService;
import com.comviva.mfs.sync.swagger.wallet.statement.models.ErrorResponse;
import com.comviva.mfs.sync.utils.LanguageAppender;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.Maps;
import io.swagger.annotations.ApiParam;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.context.request.async.DeferredResult;

import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import javax.validation.constraints.Max;
import javax.validation.constraints.Min;
import javax.validation.constraints.NotNull;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static com.comviva.mfs.common.util.TenantUtil.tenantIdOrDefault;
import static com.comviva.mfs.sync.enums.ServiceFlowIds.VALIDATE_BULK_FILE;
import static com.comviva.mfs.sync.security.Constants.LANGUAGE;
import static com.comviva.mfs.sync.security.Constants.CREATED_BY;
import static com.comviva.mfs.sync.security.Constants.WORKSPACE_ID;
import static com.comviva.mfs.sync.utils.JigsawUtils.getAuthorizationHeader;
import static com.google.common.collect.ImmutableMap.of;
import static java.util.Arrays.asList;
import static org.springframework.http.HttpStatus.BAD_REQUEST;

@javax.annotation.Generated(value = "org.openapitools.codegen.languages.SpringCodegen", date = "2021-05-03T15:01:18.351+05:30[Asia/Calcutta]")

@Controller("umsV1ApiController")
public class V1ApiController implements V1Api {

    private static final Logger LOGGER = LoggerFactory.getLogger(V1ApiController.class);
    private final NativeWebRequest request;
    private UserManagementService service;
    private ObjectMapper objectMapper;
    private MFSConfiguration configuration;
    private TxnWebApphandler txnWebApphandler;
    private BlacklistSessionsService blacklistSessionsService;
    private static final String CONTENT_DISPOSITION_KEY = "Content-Disposition";

    @Value("${unique.type.id}")
    private String uniqueType;

    @Value("${subscriber.workspace.id}")
    private String subscriberWorkspaceId;

    @Autowired
    public V1ApiController(NativeWebRequest request, MFSConfiguration configuration, ObjectMapper objectMapper, UserManagementService service, TxnWebApphandler txnWebApphandler, BlacklistSessionsService blacklistSessionsService) {
        this.request = request;
        this.configuration = configuration;
        this.objectMapper = objectMapper;
        this.service = service;
        this.txnWebApphandler = txnWebApphandler;
        this.blacklistSessionsService = blacklistSessionsService;
    }

    @Override
    public DeferredResult<ResponseEntity<AddAliasResponseModel>> addIdentifierUsingPOST(@ApiParam(value = "Authorization to pass in header") @RequestHeader(value = "Authorization", required = false) String authorization, @ApiParam(value = "Add Identifier request body. Cannot be empty.") @Valid @RequestBody(required = false) AddIdentifierRequestModel addIdentifierRequestModel) {
        Map<String, Object> requestData = objectMapper.convertValue(addIdentifierRequestModel, Map.class);
        return service.processServiceWithFlowId(requestData, "ADDIDENT", getAuthorizationHeader(request), AddAliasResponseModel.class);
    }

    @Override
    public DeferredResult<ResponseEntity<AddAliasResponseModel>> addNotificationHandlerUsingPOST(@ApiParam(value = "Authorization to pass in header") @RequestHeader(value = "Authorization", required = false) String authorization, @ApiParam(value = "Add Notification Handler request body. Cannot be empty.") @Valid @RequestBody(required = false) AddNotificationHandlerModel addNotificationHandlerModel) {
        Map<String, Object> requestData = objectMapper.convertValue(addNotificationHandlerModel, Map.class);
        return service.processServiceWithFlowId(requestData, "ADDNE", getAuthorizationHeader(request), AddAliasResponseModel.class);
    }

    @Override
    public DeferredResult<ResponseEntity<AddAliasResponseModel>> addPaymentHandleUsingPOST20(@ApiParam(value = "addPaymentHandleRequestModel", required = true) @Valid @RequestBody AddPaymentHandleRequestModel addPaymentHandleRequestModel, @ApiParam(value = "Authorization to pass in header") @RequestHeader(value = "Authorization", required = false) String authorization) {
        Map<String, Object> requestData = objectMapper.convertValue(addPaymentHandleRequestModel, Map.class);
        return service.processServiceWithFlowId(requestData, "ADDPH", getAuthorizationHeader(request), AddAliasResponseModel.class);
    }

    @Override
    public DeferredResult<ResponseEntity<BarUnBarResponseModel>> barUnbarPost(@ApiParam(value = "User Self View Session. Cannot be empty.") @RequestBody(required = false) @Valid BarUnBarRequestModel barUnBarModel) {
        String language = null;
        language = barUnBarModel.getLanguage();
        if (null == language || language.isEmpty()) {
            language = "en";
        }
        String bearerCode = "USSD";
        HttpServletResponse httpResponse = request.getNativeResponse(HttpServletResponse.class);
        TxnWebAppDTO txnWebAppDTO = TxnWebAppDTO.builder().bearerCode(bearerCode).languageCode(language).
                payload(TxnWebAppHelper.barUser(barUnBarModel, TxnConstants.BARRINGREQ,
                        txnWebApphandler.getOldTxnLanguageCode(language))).build();
        String headerStr = request.getHeader("Authorization");
        String token = null;
        if (!StringUtils.isEmpty(headerStr) && headerStr.startsWith("Bearer")) {
            token = headerStr.split(" ")[1];
        }
        String errorCode = null;
        Map output = txnWebApphandler.postRequestToTxnWebApp(txnWebAppDTO, token);
        if (output != null) {
            errorCode = (String) output.get(TxnConstants.ERROR_CODE);
            if (errorCode != null) {
                httpResponse.setStatus(Integer.valueOf(errorCode));
            }
        } else {
            httpResponse.setStatus(500);
            output = txnWebApphandler.getDefaultErrorMessage(language, bearerCode);
        }
        DeferredResult deferredResult = new DeferredResult<>();
        if (errorCode != null) {
            deferredResult.setResult(new ResponseEntity(output, HttpStatus.BAD_REQUEST));
        } else {
            deferredResult.setResult(new ResponseEntity(output, HttpStatus.OK));
        }
        return deferredResult;
    }
    public DeferredResult<ResponseEntity<UserManagementResponseModel>> serviceRequestUsingPOST11(@ApiParam(value = "Authorization to pass in header") @RequestHeader(value = "Authorization", required = false) String authorization, @ApiParam(value = "User Registration Initation service body. Cannot be empty.") @Valid @RequestBody(required = false) UserRegistrationModel userRegistrationInitationRequestModel) {
        Map<String, Object> requestData = objectMapper.convertValue(userRegistrationInitationRequestModel, Map.class);
        if (!StringUtils.isEmpty(userRegistrationInitationRequestModel.getServiceRequestId()))
            requestData.put("isDraftedRequest", "Y");
        return service.processServiceWithFlowId(requestData, "ADDUSER", getAuthorizationHeader(request), UserManagementResponseModel.class);
    }
}


package com.comviva.mfs.sync.swagger.userManagement.service;

import com.comviva.mfs.circuitbreaker.CircuitBreaker;
import com.comviva.mfs.common.data.UserContextProvider;
import com.comviva.mfs.common.util.MFSConfiguration;
import com.comviva.mfs.sync.binding.ServiceBinder;
import com.comviva.mfs.sync.handler.SyncApiHandler;
import com.comviva.mfs.sync.swagger.common.AbstractService;
import com.comviva.mfs.sync.swagger.userManagement.models.*;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.async.DeferredResult;

import java.time.LocalTime;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * Created by suresh.sahu1 on 07-04-2021.
 */
@Service
public class UserManagementService<R> extends AbstractService {

    private long asyncWaitingTimeout;

    public UserManagementService(MFSConfiguration configuration, SyncApiHandler syncApiHandler, UserContextProvider userContextProvider, @Qualifier("mfsCircuitBreaker") CircuitBreaker circuitBreaker, ServiceBinder serviceBinder) {
        super(configuration, syncApiHandler, userContextProvider, circuitBreaker, serviceBinder);
    }

    public DeferredResult processServiceWithFlowId(Map request, String flowId, String authorization, Class<R> responseClass) {
        return processRequest(request, flowId, authorization, responseClass);
    }

    public DeferredResult processResumeServiceWithFlowId(Map request, String flowId, String authorization, Class<R> responseClass) {
        return processResumeRequest(request, flowId, authorization, responseClass);
    }

    public DeferredResult processCancelServiceWithFlowId(Map request, String flowId, String authorization, Class<R> responseClass) {
        return processCancelRequest(request, flowId, authorization, responseClass);
    }

    public DeferredResult processServiceWithFlowId(Map request, String flowId, String authorization, Function<Map,Class<R>> function) {
        return processRequest(request, flowId, authorization, function);
    }

    public void waitForResult(DeferredResult deferredResult){
        asyncWaitingTimeout= configuration.getLongProperty(ASYNC_WAITING_PROPERTY, 60);
        LocalTime startTime = LocalTime.now();
        while(!deferredResult.hasResult()){
            try {
                Thread.sleep(30);
            } catch (InterruptedException e) {
                LOGGER.error("Deferred result thread error ", e);
            }
            LocalTime loopTime = LocalTime.now().minusSeconds(asyncWaitingTimeout);
            int value = loopTime.compareTo(startTime);
            if(value>0){
                deferredResult.setErrorResult(assyncResponseEntity);
                break;
            }
        }
    }

    public DeferredResult bankBalanceEnquiryCustomerUsingPOST(String authorization,
                                                              UserBankBalanceEnquiryRequest userBankBalanceEnquiryRequest,
                                                              Class<R> bankBalanceEnquiryResponseClass) {
        Map request = objectMapper.convertValue(userBankBalanceEnquiryRequest,Map.class);
        Map transactor = (Map) request.get("transactor");
        transactor.put("paymentInstrumentType","BANK");
        Map auth = new HashMap();
        auth.put("host","2");
        request.put("auth",auth);
        request.put("bankInstrumentUser","transactor");
        return processRequest(request, "BNKBALENQ", authorization, bankBalanceEnquiryResponseClass);

    }

    public DeferredResult bankMiniStatementCustomerUsingPOST(String authorization,
                                                             UserMiniStatementRequest userMiniStatementRequest,
                                                              Class<R> miniStatementEnquiryResponse) {
        Map request = objectMapper.convertValue(userMiniStatementRequest,Map.class);
        Map transactor = (Map) request.get("transactor");
        transactor.put("paymentInstrumentType","BANK");
        Map auth = new HashMap();
        auth.put("host","2");
        request.put("auth",auth);
        request.put("bankInstrumentUser","transactor");
        return processRequest(request, "BAMINISTMT", authorization, miniStatementEnquiryResponse);

    }

    public DeferredResult<ResponseEntity<ChangePinResponseNew>> newChangePin(Map<String, Object> requestBody, String flowId, String authorizationHeader, Class<ChangePinResponseNew> changePinResponseNewClass) {
        return processRequest(requestBody,flowId,authorizationHeader,changePinResponseNewClass);
    }

    public DeferredResult<ResponseEntity<RequestEStatementResponse>> requestEstatement(Map<String, Object> requestBody, String flowId, String authorizationHeader, Class<RequestEStatementResponse> requestEStatementResponseClass) {
        return processRequest(requestBody,flowId,authorizationHeader,requestEStatementResponseClass);
    }

    public DeferredResult<ResponseEntity<UpdateEStatPrefResponse>> updateEstatement(Map<String, Object> requestBody, String flowId, String authorizationHeader, Class<UpdateEStatPrefResponse> updateEStatPrefResponseClass) {
        return processRequest(requestBody,flowId,authorizationHeader,updateEStatPrefResponseClass);
    }

    public DeferredResult<ResponseEntity<SaveOrUpdateUserPreferencesRes>> saveOrUpdateUserPreferences(Map requestBody, String authorizationHeader) {
        return processRequest(requestBody,"SAVE_OR_UPDATE_USER_PREF",authorizationHeader,SaveOrUpdateUserPreferencesRes.class);
    }

    public DeferredResult<ResponseEntity<DeleteAliasResponse>> deleteAlias(Map requestMap, String authorizationHeader) {
        return processRequest(requestMap,"DELETEALIAS",authorizationHeader,DeleteAliasResponse.class);
    }

    public DeferredResult<ResponseEntity<DeleteAliasResponse>> deleteAliasResume(Map requestMap, String authorizationHeader) {
        return processResumeRequest(requestMap,"DELETEALIAS",authorizationHeader,DeleteAliasResponse.class);
    }

    public DeferredResult<ResponseEntity<GetUserPreferencesRes>> getUserPreferences(Map requestBody, String authorizationHeader) {
        return processRequest(requestBody,"GET_USR_PREFERENCES",authorizationHeader,GetUserPreferencesRes.class);
    }

    public DeferredResult<ResponseEntity<CheckQnaResponse>> checkQna(Map requestMap, String authorizationHeader) {
        return processRequest(requestMap,"CHECKQNAEXIST",authorizationHeader,CheckQnaResponse.class);
    }
}
package com.comviva.mfs.sync.swagger.common;

import com.comviva.mfs.circuitbreaker.CircuitBreaker;
import com.comviva.mfs.common.data.UserContextProvider;
import com.comviva.mfs.common.util.JsonUtil;
import com.comviva.mfs.common.util.MFSConfiguration;
import com.comviva.mfs.common.util.TenantUtil;
import com.comviva.mfs.edr.writer.EDRWriter;
import com.comviva.mfs.sync.binding.ServiceBinder;
import com.comviva.mfs.sync.config.JwtReader;
import com.comviva.mfs.sync.config.RedisProperties;
import com.comviva.mfs.sync.controller.FilteringDeferredResult;
import com.comviva.mfs.sync.controller.RequestBodyProcessor;
import com.comviva.mfs.sync.controller.SwaggerResponseConverterDeferredResult;
import com.comviva.mfs.sync.dto.MoneyResponseDTO;
import com.comviva.mfs.sync.exception.*;
import com.comviva.mfs.sync.handler.SyncApiHandler;
import com.comviva.mfs.sync.service.*;
import com.comviva.mfs.sync.swagger.authorization.profile.exceptions.AuthorizationProfileException;
import com.comviva.mfs.sync.swagger.order.management.exceptions.*;
import com.comviva.mfs.sync.swagger.wallet.statement.exception.DownloadReceiptException;
import com.comviva.mfs.sync.swagger.wallet.statement.exception.TransactionDetailsException;
import com.comviva.mfs.sync.swagger.wallet.statement.exception.TransactionSummaryException;
import com.comviva.mfs.sync.swagger.wallet.statement.exception.WalletStatementException;
import com.comviva.mfs.sync.swagger.wallet.statement.exception.TransactionDetailsByExtRefIdException;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import lombok.AllArgsConstructor;
import lombok.Data;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.*;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.ObjectUtils;
import org.springframework.util.StopWatch;
import org.springframework.web.context.request.async.DeferredResult;

import java.time.LocalTime;
import java.util.*;
import java.util.function.Function;
import java.util.function.Predicate;

import static com.comviva.mfs.common.tenantInfo.TenantInfo.TENANT_ID_KEY;
import static com.comviva.mfs.common.util.Constants.CANCEL_SERVICE_REQUEST_ID;
import static com.comviva.mfs.common.util.Constants.RESUME_SERVICE_REQUEST_ID;
import static com.comviva.mfs.sync.security.Constants.IDENTIFIER_TYPE;
import static com.comviva.mfs.sync.security.Constants.IDENTIFIER_VALUE;
import static com.comviva.mfs.sync.security.Constants.USER_ID;
import static com.comviva.mfs.sync.utils.JigsawUtils.populateClaimsIntoRequest;
import static java.util.Optional.of;
import static org.springframework.http.HttpStatus.SERVICE_UNAVAILABLE;

public abstract class AbstractService<T,R> {

    @Autowired
    protected ObjectMapper objectMapper;

    @Autowired
    private JwtReader jwtReader;

    @Autowired
    private EDRWriter edrWriter;

    @Autowired
    private BlacklistSessionsService blacklistSessionsService;

    private final String GET_FEES_OAP = "GETFEESOAP";
    private final String RECEIVER = "receiver";
    private final String SENDER = "sender";
    private final String PRODUCT_ID = "productId";
    protected static final Logger LOGGER = LoggerFactory.getLogger(AbstractService.class);
    public static final String CREATE_API_ROUTING_KEY_PROPERTY = "syncapi.create.service.request.routingKey";
    public static final String RESUME_API_ROUTING_KEY_PROPERTY = "syncapi.resume.service.request.routingKey";
    public static final String CANCEL_API_ROUTING_KEY_PROPERTY = "syncapi.cancel.service.request.routingKey";
    public static final String RESULT_TIMEOUT_PROPERTY = "syncapi.result.timeOutInMillis";
    public static final String ASYNC_WAITING_PROPERTY = "syncapi.result.asyncWaitInSeconds";
    public static final String RESULT_TIMEOUT_MSG_PROPERTY = "syncapi.result.timeOutMsg";
    public static final long DEFAULT_RESULT_TIMEOUT = 5000l;
    public static final String DEFAULT_TIMEOUT_MESSAGE = "Request to backend timed out";
    public static final String STATUS_KEY = "status";
    protected static final String ERROR_KEY = "errors";
    protected static final String MESSAGE_KEY = "message";
    protected static final String ERROR_CODE_KEY = "code";
    protected static final String OTP = "otp";
    protected static final String TRANSACTION_TIME_OUT_CODE = "response.time.out";
    protected static final String ASYNC_WAITING_CODE = "response.async.waiting";
    private static final String INITIATOR = "initiator";
    private static final String REQUESTER = "requester";
    private static final String TOKEN_IS_BLANK = "token.is.blank";
    private static final String TOKEN_IS_BLANK_MESSAGE = "authorization token is mandatory";
    private static final String TOKEN_IS_INVALID = "token.is.invalid";
    private static final String TOKEN_IS_INVALID_MESSAGE = "authorization token is invalid";
    private static final String SESSION_IS_INVALID = "session.logged.out";
    private static final String SESSION_IS_INVALID_MESSAGE = "User already logged out from the system";
    private static final String REQUEST_IS_EMPTY = "request.is.empty";
    private static final String REQUEST_IS_EMPTY_MESSAGE = "request cannot be empty";
    private static final String ERRORS = "errors";
    private static final String INVALID_TOKEN_VALUE_FORMAT = "invalid.token.value.format";
    private static final String INVALID_TOKEN_VALUE_FORMAT_MESSAGE = "token value should be in format 'Bearer <token_value>'";
    protected ResponseEntity timeOutResponseEntity;
    protected ResponseEntity assyncResponseEntity;

    protected MFSConfiguration configuration;
    protected CircuitBreaker circuitBreaker;
    protected final SyncApiHandler syncApiHandler;
    protected final UserContextProvider userContextProvider;

    protected final String createRequestRoutingKey;
    protected final String resumeRequestRoutingKey;
    protected final String cancelRequestRoutingKey;
    protected long resultTimeout;
    private long asyncWaitingTimeout;
    private final String asyncWaiting;
    protected final String timeoutMsg;
    protected final RequestBodyProcessor requestBodyProcessor;
    protected final String trackingDataHeader = "false";
    protected final String tenantId = "";
    protected final Predicate<Map> pauseRequestFilter = new Predicate<Map>() {
        @Override
        public boolean test(Map result) {
            return "third.party.async.wait".equals(result.getOrDefault("code", "none"));
        }
    };
    protected final Predicate<MoneyResponseDTO> pauseMoneyRequestFilter = new Predicate<MoneyResponseDTO>() {
        @Override
        public boolean test(MoneyResponseDTO result) {
            return "third.party.async.wait".equals(result.getCode());
        }
    };

    protected ServiceBinder serviceBinder;

    private final String serviceFlowIds;
    public static final String SERVICE_FLOW_IDS = "service.flow.ids";
    private static final String NOT_ALLOWED_TO_PERFORM = "not.allowed.to.perform.service";
    private static final String NOT_ALLOWED_TO_PERFORM_MESSAGE = "Requested service is not allowed to perform";

    private boolean isRedisEnabled = false;

    @Autowired
    public AbstractService(MFSConfiguration configuration, SyncApiHandler syncApiHandler,
                           UserContextProvider userContextProvider,
                           @Qualifier("mfsCircuitBreaker") CircuitBreaker circuitBreaker,
                           ServiceBinder serviceBinder) {
        this.configuration = configuration;
        this.syncApiHandler = syncApiHandler;
        this.userContextProvider = userContextProvider;
        this.circuitBreaker = circuitBreaker;
        this.serviceBinder = serviceBinder;
        createRequestRoutingKey = serviceBinder.getCreateRequestRoutingKey();
        resumeRequestRoutingKey = serviceBinder.getResumeRequestRoutingKey();
        cancelRequestRoutingKey = serviceBinder.getCancelRequestRoutingKey();

        resultTimeout = configuration.getLongProperty(RESULT_TIMEOUT_PROPERTY, DEFAULT_RESULT_TIMEOUT);
        asyncWaitingTimeout= configuration.getLongProperty(ASYNC_WAITING_PROPERTY, 60);
        timeoutMsg = configuration.getProperty(RESULT_TIMEOUT_MSG_PROPERTY, DEFAULT_TIMEOUT_MESSAGE);
        asyncWaiting = configuration.getProperty(RESULT_TIMEOUT_MSG_PROPERTY, DEFAULT_TIMEOUT_MESSAGE);
        serviceFlowIds=configuration.getProperty(SERVICE_FLOW_IDS);
        requestBodyProcessor = new RequestBodyProcessor(configuration);
        HashMap<String, Object> timeOutResult = new HashMap<>();
        HashMap<String, String> errors = new HashMap<>();
        errors.put(ERROR_CODE_KEY, TRANSACTION_TIME_OUT_CODE);
        errors.put(MESSAGE_KEY, timeoutMsg);
        List errorsList = new ArrayList<>();
        errorsList.add(errors);
        timeOutResult.put(ERROR_KEY, errorsList);
        timeOutResult.put(STATUS_KEY, "FAILED");
        timeOutResponseEntity = ResponseEntity.status(HttpStatus.GATEWAY_TIMEOUT).body(timeOutResult);

        HashMap<String, Object> asyncWaitingResult = new HashMap<>();
        HashMap<String, String> asyncWaitingerrors = new HashMap<>();
        errors.put(ERROR_CODE_KEY, ASYNC_WAITING_CODE);
        errors.put(MESSAGE_KEY, asyncWaiting);
        List syncWaitingerrorsList = new ArrayList<>();
        syncWaitingerrorsList.add(errors);
        asyncWaitingResult.put(ERROR_KEY, syncWaitingerrorsList);
        asyncWaitingResult.put(STATUS_KEY, "PENDING");
        assyncResponseEntity = ResponseEntity.status(HttpStatus.GATEWAY_TIMEOUT).body(timeOutResult);
        isRedisEnabled = configuration.getBooleanProperty("redis.enabled");
    }

    protected void initTenantContext(Map requestData, String tenantId) {
        if (StringUtils.isNotBlank(tenantId)) {
            TenantUtil.addTenantIdToContext(tenantId);
            requestData.put(TENANT_ID_KEY, tenantId);
        }
    }

    protected DeferredResult<Map> rejectRequestMoney() {
        LOGGER.debug("Create Service Request Rejected - Circuit Breaker is open");
        final DeferredResult<Map> deferredResult = new DeferredResult<>();
        Map<String, String> response = ImmutableMap.of(STATUS_KEY, "Circuit breaker is open");
        deferredResult.setErrorResult(new ResponseEntity<Map>(response, SERVICE_UNAVAILABLE));
        return deferredResult;
    }

    protected DeferredResult<Map> submitMoneyRequest(String flowId, String trackingId, Map requestData,
                                                     String routingKey, boolean needTrackingData, boolean syncFlow) {
        resultTimeout = configuration.getLongProperty(RESULT_TIMEOUT_PROPERTY, DEFAULT_RESULT_TIMEOUT);
        LOGGER.debug("configured resultTimeout   {}", resultTimeout);
        final DeferredResult<Map> deferredResult = syncFlow ? new FilteringDeferredResult<>(resultTimeout, timeOutResponseEntity,
                pauseRequestFilter) : new DeferredResult<>(resultTimeout, timeOutResponseEntity);
        syncApiHandler.submitServiceRequest(flowId, trackingId, requestData,
                routingKey, deferredResult, null, needTrackingData, false);

        LocalTime startTime = LocalTime.now();
        while(!deferredResult.hasResult()){
            try {
                Thread.sleep(30);
            } catch (InterruptedException e) {
                LOGGER.error("Deferred result thread error ", e);
            }
            LocalTime loopTime = LocalTime.now().minusSeconds(asyncWaitingTimeout);
            int value = loopTime.compareTo(startTime);
            if(value>0){
                deferredResult.setErrorResult(assyncResponseEntity);
                break;
            }
        }
        return deferredResult;
    }

    protected boolean needTrackingData(String trackingDataHeader) {
        if (StringUtils.isBlank(trackingDataHeader)) {
            return false;
        }
        return Boolean.valueOf(trackingDataHeader.trim());
    }

    protected Map processRequest(T request,String flowId, String authorization){
        objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
        Map<String, Object> requestData = objectMapper.convertValue(request, Map.class);
        LOGGER.debug("request = {}",request);
        addJwtClaims(requestData,authorization);
        if(GET_FEES_OAP.equalsIgnoreCase(flowId)){
            Map receiver = (Map) requestData.get(RECEIVER);
            LOGGER.debug("receiver = {}",receiver);
            if(!ObjectUtils.isEmpty(receiver) && !receiver.containsKey(PRODUCT_ID)){
                receiver.put(PRODUCT_ID,"12");
            }
            String senderUserType=(String) requestData.getOrDefault("senderUserType","registered");
            if(senderUserType.equals("guest")){
                Map sender = (Map) requestData.get(SENDER);
                sender.put("partyId",(String)sender.get("idValue"));
            }

        }
        initTenantContext(requestData, tenantId);
        requestBodyProcessor.process(requestData);
        LOGGER.debug("Received Create Service Request(Flow Id: {},Tracking: {}): {} ", flowId, trackingDataHeader, requestData);
        if (circuitBreaker.isOpen()) {
            throw new CircuitOpenException();
        }
        DeferredResult<Map> deferredResult= submitMoneyRequest(flowId,null, requestData, createRequestRoutingKey,
                needTrackingData(trackingDataHeader), false);
        Map response = resolveResult(deferredResult);
        throwExceptionIfRequired(flowId,response);
        return response;
    }

    protected Map processResumeRequest(T request,String flowId){
        Map<String, Object> requestData = objectMapper.convertValue(request, Map.class);
        initTenantContext(requestData, tenantId);
        requestBodyProcessor.process(requestData);
        LOGGER.debug("Received Resume Service Request(Flow Id: {},Tracking: {}): {} ",
                flowId, trackingDataHeader, requestData);
        if (circuitBreaker.isOpen()) {
            throw new CircuitOpenException();
        }
        final String resumeRequestId = (String) requestData.get(RESUME_SERVICE_REQUEST_ID);
        DeferredResult<Map> deferredResult= submitMoneyRequest(flowId, resumeRequestId, requestData, resumeRequestRoutingKey,
                needTrackingData(trackingDataHeader), false);
        Map response = resolveResult(deferredResult);
        LOGGER.debug("Abstract service :: processRequest -> Response :: {}", JsonUtil.toJson(response));
        throwExceptionIfRequiredForResume(flowId,response);
        return response;
    }

    protected DeferredResult processDeferredResumeRequest(T request,String flowId){
        final StopWatch stopWatch = new StopWatch();

        Map EDRData = new HashMap();
        EDRData.put("flowId",flowId);
        EDRData.put("startTime", new Date().toString());
        stopWatch.start();
        Map<String, Object> requestData = objectMapper.convertValue(request, Map.class);
        initTenantContext(requestData, tenantId);
        requestBodyProcessor.process(requestData);
        LOGGER.debug("Received Resume Service Request(Flow Id: {},Tracking: {}): {} ",
                flowId, trackingDataHeader, requestData);
        if (circuitBreaker.isOpen()) {
            throw new CircuitOpenException();
        }
        final String resumeRequestId = (String) requestData.get(RESUME_SERVICE_REQUEST_ID);
        DeferredResult<Map> deferredResult= submitMoneyRequest(flowId, resumeRequestId, requestData, resumeRequestRoutingKey,
                needTrackingData(trackingDataHeader), false);
        Map response = resolveResult(deferredResult);
        throwExceptionIfRequiredForResume(flowId,response);
        attachCaptureEDRDataAsCallBack(stopWatch,EDRData,requestData,deferredResult);
        return deferredResult;
    }


    protected Map processCancelRequest(T request,String flowId){
        Map<String, Object> requestData = objectMapper.convertValue(request, Map.class);
        initTenantContext(requestData, tenantId);
        requestBodyProcessor.process(requestData);
        LOGGER.debug("Received Cancel Service Request(Flow Id: {},Tracking: {}): {} ",
                flowId, trackingDataHeader, requestData);
        if (circuitBreaker.isOpen()) {
            throw new CircuitOpenException();
        }
        final String cancelServiceRequestId = (String) requestData.get(CANCEL_SERVICE_REQUEST_ID);
        DeferredResult<Map> deferredResult= submitMoneyRequest(flowId, cancelServiceRequestId, requestData, cancelRequestRoutingKey,
                needTrackingData(trackingDataHeader), false);
        Map response = resolveResult(deferredResult);
        throwExceptionIfRequiredForCancel(flowId,response);
        return response;
    }

    protected DeferredResult processDeferredCancelRequest(T request,String flowId){
        final StopWatch stopWatch = new StopWatch();

        Map EDRData = new HashMap();
        EDRData.put("flowId",flowId);
        EDRData.put("startTime", new Date().toString());
        stopWatch.start();
        Map<String, Object> requestData = objectMapper.convertValue(request, Map.class);
        initTenantContext(requestData, tenantId);
        requestBodyProcessor.process(requestData);
        LOGGER.debug("Received Cancel Service Request(Flow Id: {},Tracking: {}): {} ",
                flowId, trackingDataHeader, requestData);
        if (circuitBreaker.isOpen()) {
            throw new CircuitOpenException();
        }
        final String cancelServiceRequestId = (String) requestData.get(CANCEL_SERVICE_REQUEST_ID);
        DeferredResult<Map> deferredResult= submitMoneyRequest(flowId, cancelServiceRequestId, requestData, cancelRequestRoutingKey,
                needTrackingData(trackingDataHeader), false);
        Map response = resolveResult(deferredResult);
        throwExceptionIfRequiredForCancel(flowId,response);
        attachCaptureEDRDataAsCallBack(stopWatch,EDRData,requestData,deferredResult);
        return deferredResult;
    }

    protected Map resolveResult(DeferredResult<Map> deferredResult) {
        return  of(deferredResult.getResult()).
                filter(r -> r instanceof ResponseEntity).
                map(r -> (ResponseEntity) r).
                map(r -> objectMapper.convertValue(r.getBody(),Map.class)).
                orElse(objectMapper.convertValue(deferredResult.getResult(),Map.class));
    }

    private void throwExceptionIfRequiredForResume(String flowId, Map response) {
        if(hasErrors(response)){
            throw new OrderCancellationApprovalException(response,flowId,"order cancellation approval failed");
        }
    }

    private void throwExceptionIfRequiredForCancel(String flowId, Map response) {
        if(hasErrors(response)){
            throw new OrderCancellationRejectionException(response,flowId,"order cancellation rejection failed");
        }
    }

    private void throwExceptionIfRequired(String flowId, Map<String , Object> response) {
        if(hasErrors(response)){
            switch (flowId){
                case GET_FEES_OAP   : throw new ServiceChargeCalculationException(response,flowId,"charge calculation failed");
                case "CANCELORDER"  : throw new OrderCancellationException(response,flowId,"Order cancellation failed");
                case "USRSTMT"      :
                case "ADMUSRSTMT"   :
                    throw new WalletStatementException(response,flowId,"Fetch Wallet Statement Failed");
                case "ADMTXNDTLS"   :
                case "USRTXNDTLS"      :
                    throw new TransactionDetailsException(response,flowId,"Fetch Transaction Details Failed");
                case "TXNSUMRY_V3"   :
                    throw new TransactionSummaryException(response,flowId,"Fetch transaction Summary Failed");
                case "ADMDOWNLOADRECEIPT" :
                case "DOWNLOADRECEIPT": throw new DownloadReceiptException(response,flowId,"Download Receipt Failed");
                case "TXNREFID"   : throw new TransactionDetailsByExtRefIdException(response,flowId,"Fetch Transaction Details By External Reference Id Failed");
                default:            throw new OrderCreationFailedException(response,flowId,"order creation failed");
            }
        }
    }


    public boolean hasErrors(Map response) {
        return response.containsKey("errors");
    }

    private void validateToken(Map requestData, String authToken) {
//        if(StringUtils.isEmpty(authToken)){
//            throw new AuthorizationProfileException(populateErrorCodeAndMessage(TOKEN_IS_BLANK,TOKEN_IS_BLANK_MESSAGE,requestData));
//        }
    }

    private Map populateErrorCodeAndMessage(String errorCode, String errorMessage, Map requestData) {
        Map error = Maps.newHashMap();
        error.put("code",errorCode);
        error.put("message",errorMessage);
        requestData.put(ERRORS, Lists.newArrayList(error));
        return requestData;
    }

    public DeferredResult processRequest(T request, String flowId, String authToken,Class<R> responseClass){
        LOGGER.debug("inside processRequest()");
        final StopWatch stopWatch = new StopWatch();

        Map EDRData = new HashMap();
        EDRData.put("flowId",flowId);
        EDRData.put("startTime", new Date().toString());
        stopWatch.start();

        Map<String, Object> requestData = resolveRequest(request);
        validateToken(requestData,authToken);
        addJwtClaims(requestData,authToken);
        isSystemUserPerformingTheService(requestData, flowId);
        LOGGER.debug("requestData 1: {}",requestData);
        objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
        initTenantContext(requestData, tenantId);
        requestBodyProcessor.process(requestData);
        LOGGER.debug("requestData 2: {}",requestData);
        LOGGER.debug("Received Create Service Request(Flow Id: {},Tracking: {}): {} ", flowId, trackingDataHeader, requestData);
        if (circuitBreaker.isOpen()) {
            return rejectRequestMoney();
        }
        DeferredResult deferredResult =  submitMoneyRequest(flowId,null, requestData, createRequestRoutingKey,
                needTrackingData(trackingDataHeader), false,responseClass);
        attachCaptureEDRDataAsCallBack(stopWatch,EDRData,requestData,deferredResult);
        return deferredResult;
    }
    public DeferredResult processRequest(T request, String flowId, String authToken,Class<R> responseClass, boolean syncFlow){

        final StopWatch stopWatch = new StopWatch();

        Map EDRData = new HashMap();
        EDRData.put("flowId",flowId);
        EDRData.put("startTime", new Date().toString());
        stopWatch.start();

        Map<String, Object> requestData = resolveRequest(request);
        validateToken(requestData,authToken);
        addJwtClaims(requestData,authToken);
        objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
        initTenantContext(requestData, tenantId);
        requestBodyProcessor.process(requestData);
        LOGGER.debug("Received Create Service Request(Flow Id: {},Tracking: {}): {} ", flowId, trackingDataHeader, requestData);
        if (circuitBreaker.isOpen()) {
            return rejectRequestMoney();
        }
        DeferredResult deferredResult =  submitMoneyRequest(flowId,null, requestData, createRequestRoutingKey,
                needTrackingData(trackingDataHeader), syncFlow,responseClass);
        attachCaptureEDRDataAsCallBack(stopWatch,EDRData,requestData,deferredResult);
        return deferredResult;
    }

    public DeferredResult processRequest(T request, String flowId, String authToken, Function<Map,Class<R>> function){
        final StopWatch stopWatch = new StopWatch();

        Map EDRData = new HashMap();
        EDRData.put("flowId",flowId);
        EDRData.put("startTime", new Date().toString());
        stopWatch.start();

        Map<String, Object> requestData = resolveRequest(request);
        validateToken(requestData,authToken);
        addJwtClaims(requestData,authToken);
        objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
        initTenantContext(requestData, tenantId);
        requestBodyProcessor.process(requestData);
        LOGGER.debug("Received Create Service Request(Flow Id: {},Tracking: {}): {} ", flowId, trackingDataHeader, requestData);
        if (circuitBreaker.isOpen()) {
            return rejectRequestMoney();
        }
        DeferredResult deferredResult = submitMoneyRequest(flowId,null, requestData, createRequestRoutingKey,
                needTrackingData(trackingDataHeader), false,function);
        attachCaptureEDRDataAsCallBack(stopWatch,EDRData,requestData,deferredResult);
        return deferredResult;
    }

    protected DeferredResult processResumeRequest(T request,String flowId, String authToken,Class<R> responseClass){
        final StopWatch stopWatch = new StopWatch();

        Map EDRData = new HashMap();
        EDRData.put("flowId",flowId);
        EDRData.put("startTime", new Date().toString());
        stopWatch.start();
        Map<String, Object> requestData = resolveRequest(request);
        validateToken(requestData,authToken);
        addJwtClaims(requestData,authToken);
        initTenantContext(requestData, tenantId);
        requestBodyProcessor.process(requestData);
        LOGGER.debug("Received Resume Service Request(Flow Id: {},Tracking: {}): {} ",
                flowId, trackingDataHeader, requestData);
        if (circuitBreaker.isOpen()) {
            throw new CircuitOpenException();
        }
        final String resumeRequestId = (String) requestData.get(RESUME_SERVICE_REQUEST_ID);
        DeferredResult deferredResult = submitMoneyRequest(flowId, resumeRequestId, requestData, resumeRequestRoutingKey,
                needTrackingData(trackingDataHeader), false,responseClass);
        attachCaptureEDRDataAsCallBack(stopWatch,EDRData,requestData,deferredResult);

        return deferredResult;

    }

    protected DeferredResult processCancelRequest(T request,String flowId, String authToken,Class<R> responseClass){
        final StopWatch stopWatch = new StopWatch();

        Map EDRData = new HashMap();
        EDRData.put("flowId",flowId);
        EDRData.put("startTime", new Date().toString());
        stopWatch.start();
        Map<String, Object> requestData = resolveRequest(request);
        validateToken(requestData,authToken);
        addJwtClaims(requestData,authToken);
        initTenantContext(requestData, tenantId);
        requestBodyProcessor.process(requestData);
        LOGGER.debug("Received Cancel Service Request(Flow Id: {},Tracking: {}): {} ",
                flowId, trackingDataHeader, requestData);
        if (circuitBreaker.isOpen()) {
            throw new CircuitOpenException();
        }
        final String cancelServiceRequestId = (String) requestData.get(CANCEL_SERVICE_REQUEST_ID);
        DeferredResult deferredResult = submitMoneyRequest(flowId, cancelServiceRequestId, requestData, cancelRequestRoutingKey,
                needTrackingData(trackingDataHeader), false,responseClass);
        attachCaptureEDRDataAsCallBack(stopWatch,EDRData,requestData,deferredResult);
        return deferredResult;
    }


    private Map<String, Object> resolveRequest(T request) {
        if(request instanceof Map){
            return (Map<String, Object>) request;
        }else {
            return objectMapper.convertValue(request, Map.class);
        }
    }

    private DeferredResult submitMoneyRequest(String flowId, String trackingId, Map requestData, String routingKey,
                                              boolean needTrackingData, boolean syncFlow, Class<R> responseClass) {
        resultTimeout = configuration.getLongProperty(RESULT_TIMEOUT_PROPERTY, DEFAULT_RESULT_TIMEOUT);
        LOGGER.debug("configured resultTimeout   {}", resultTimeout);
        final DeferredResult deferredResult = syncFlow?new SwaggerResponseConverterDeferredResult<>(resultTimeout, timeOutResponseEntity,responseClass,pauseRequestFilter):
                new SwaggerResponseConverterDeferredResult<>(resultTimeout, timeOutResponseEntity,jwtReader,isRedisEnabled,responseClass);
        syncApiHandler.submitServiceRequest(flowId, trackingId, requestData,
                routingKey, deferredResult, null, needTrackingData, false);
        return deferredResult;
    }

    private DeferredResult submitMoneyRequest(String flowId, String trackingId, Map requestData, String routingKey,
                                              boolean needTrackingData, boolean syncFlow,Function<Map,Class<R>> function) {
        resultTimeout = configuration.getLongProperty(RESULT_TIMEOUT_PROPERTY, DEFAULT_RESULT_TIMEOUT);
        LOGGER.debug("configured resultTimeout   {}", resultTimeout);
        final DeferredResult deferredResult = new SwaggerResponseConverterDeferredResult<>(resultTimeout, timeOutResponseEntity,function);
        syncApiHandler.submitServiceRequest(flowId, trackingId, requestData,
                routingKey, deferredResult, null, needTrackingData, false);
        return deferredResult;
    }

    protected void addJwtClaims(Map request,String authToken){
        LOGGER.debug("Add Jwt Claims, request={}, authToken={}", request, authToken);
        if(StringUtils.isEmpty(authToken) && request.containsKey("isTokenRequired") && null!= (String)request.get("isTokenRequired") && Boolean.valueOf((String)request.get("isTokenRequired"))){
            throw new AuthorizationProfileException(populateErrorCodeAndMessage(TOKEN_IS_BLANK,TOKEN_IS_BLANK_MESSAGE,request));
        }else if(StringUtils.isEmpty(authToken)){
            return;
        }
        String token[] = authToken.split(" ");
        if(!StringUtils.isEmpty(token[0]) && token[0].trim().equals("Basic")){
            return;
        }
        if(token.length != 2){
            throw new AuthorizationProfileException(populateErrorCodeAndMessage(INVALID_TOKEN_VALUE_FORMAT,INVALID_TOKEN_VALUE_FORMAT_MESSAGE,request));
        }
        if(StringUtils.isEmpty(token[1])){
            throw new AuthorizationProfileException(populateErrorCodeAndMessage(TOKEN_IS_BLANK,TOKEN_IS_BLANK_MESSAGE,request));
        }
        LOGGER.debug("token = {}",token[1]);
        Map claims;
        try {
            claims = jwtReader.jwtReader(token[1]);
        }catch (Exception e){
            throw new AuthorizationProfileException(populateErrorCodeAndMessage(TOKEN_IS_INVALID,TOKEN_IS_INVALID_MESSAGE,request));
        }
        if(ObjectUtils.isEmpty(claims)){
            throw new AuthorizationProfileException(populateErrorCodeAndMessage(TOKEN_IS_INVALID,TOKEN_IS_INVALID_MESSAGE,request));
        }
        //Check if session id is black listed or not.
        LOGGER.debug("Claims form token: {}", claims);
        if (claims.get("user_name") != null) {
            LOGGER.debug("Check if session id is black listed or not");
            String sessionId = (String) claims.get("user_name");
            LOGGER.debug("Session id: {}", sessionId);
            boolean result = blacklistSessionsService.isSessionIdBlacklisted(sessionId);
            LOGGER.debug("Blacklisted: {}", result);
            if (result) {
                throw new UnauthorizedRequestException(populateErrorCodeAndMessage(SESSION_IS_INVALID, SESSION_IS_INVALID_MESSAGE, request));
            }
        }
        populateClaimsIntoRequest(request,claims);
    }

    public void validateRequestBody(Map request) {
        if(ObjectUtils.isEmpty(request)){
            throw new AuthorizationProfileException(populateErrorCodeAndMessage(REQUEST_IS_EMPTY,REQUEST_IS_EMPTY_MESSAGE,request));
        }
    }

    @AllArgsConstructor
    @Data
    class EDRContext{
        StopWatch stopWatch;
        Map edrData;
        Map requestData;
        DeferredResult<Map> response;
    }

    private void captureEDRData(EDRContext context){
        context.getEdrData().put("endTime", new Date().toString());
        context.getStopWatch().stop();
        context.getEdrData().put("responseTime", context.getStopWatch().getTotalTimeMillis());
        edrWriter.prepareEDR(context.getEdrData(), context.getRequestData(),context.getResponse());
    }

    private void attachCaptureEDRDataAsCallBack(StopWatch stopWatch, Map edrData, Map<String, Object> requestData, DeferredResult<Map> deferredResult) {
        deferredResult.onCompletion(() -> captureEDRData(new EDRContext(stopWatch,edrData,requestData,deferredResult)));
    }

    protected void populateTransactorDetailsFromToken(Map<String, Object> request){
        Map<String, Object> map = (Map) request.get("jwtClaims");
        Map<String, Object> transactor = new HashMap<>();
        if(!ObjectUtils.isEmpty(map.get(IDENTIFIER_TYPE))){
            transactor.put("idType",map.get(IDENTIFIER_TYPE));
        }
        if(!ObjectUtils.isEmpty(map.get(IDENTIFIER_VALUE))){
            transactor.put("idValue",map.get(IDENTIFIER_VALUE));
        }
        if(!ObjectUtils.isEmpty(map.get(USER_ID))){
            transactor.put(USER_ID,map.get(USER_ID));
        }
        if(!transactor.isEmpty()){
            request.put("initiator","transactor");
            request.put("transactor",transactor);
        }
    }

    private void  isSystemUserPerformingTheService(Map<String, Object> requestData, String requestedFlowId){
        String tokenType = (String) requestData.get("tokenType");
        if ("systemToken".equalsIgnoreCase(tokenType) && serviceFlowIds.equalsIgnoreCase(requestedFlowId)){
            throw new AuthorizationProfileException(populateErrorCodeAndMessage(NOT_ALLOWED_TO_PERFORM,NOT_ALLOWED_TO_PERFORM_MESSAGE,requestData));
        }
    }

}

package com.comviva.mfs.sync.controller;

import com.comviva.mfs.common.cryptography.TextEncryptor;
import com.comviva.mfs.common.util.MFSConfiguration;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.Stack;

import static com.comviva.mfs.common.util.Constants.MFS_SENSITIVE_FIELDS_ENCRYPTION_SALT;
import static com.comviva.mfs.sync.utils.JigsawUtils.populateClaimsIntoRequest;

public class RequestBodyProcessor {

    public static final String PROTECTED_FIELDS_PROPERTY = "mfs.sensitive.fields";
    public static final String PROTECTED_FIELDS_EXCLUDE_PROPERTY = "mfs.sensitive.fields.exclude";
    private final TextEncryptor textEncryptor;
    private final String[] fieldNames;
    private final String[] excludeFieldNames;

    public RequestBodyProcessor(MFSConfiguration configuration) {
        this.fieldNames = configuration.getPropertyValues(PROTECTED_FIELDS_PROPERTY);
        this.excludeFieldNames = configuration.getPropertyValues(PROTECTED_FIELDS_EXCLUDE_PROPERTY);
        this.textEncryptor = new TextEncryptor(configuration.getProperty(MFS_SENSITIVE_FIELDS_ENCRYPTION_SALT),
                configuration.getProperty(MFS_SENSITIVE_FIELDS_ENCRYPTION_SALT));
    }

    private void maskKeys(Map requestBody) {
        Stack<Map> payload = new Stack<>();
        payload.push(requestBody);
        while (!payload.empty()) {
            final Map currentMap = payload.pop();
            for (String fieldName : fieldNames) {
                maskKey(fieldName, currentMap);
            }
            for (Object object : currentMap.entrySet()) {
                Map.Entry entry = (Map.Entry) object;
                if (entry.getValue() instanceof Map && notExcluded(entry.getKey())) {
                    payload.push((Map) entry.getValue());
                }
            }
        }
    }

    private void maskKey(String key, Map currentMap) {
        //This is inefficient - need to make this better
        String keyToMask;
        Set set = new HashMap(currentMap).keySet();
        for (Object k : set) {
            if (!(k instanceof String)) {
                continue;
            }
            keyToMask = (String) k;
            if (keyToMask.equalsIgnoreCase(key) && notExcluded(keyToMask)) {
                currentMap.put(key, maskValue(currentMap.get(key)));
            }
        }
    }

    private boolean notExcluded(Object key) {
        return !(key instanceof String) || notExcluded((String) key);
    }

    private boolean notExcluded(String key) {
        for (String excludeFieldName : excludeFieldNames) {
            if (excludeFieldName.equalsIgnoreCase(key)) {
                return false;
            }
        }
        return true;
    }

    private Object maskValue(Object value) {
        if (!(value instanceof String)) {
            return value;
        }
        if (StringUtils.isEmpty(value))
            return value;

        return textEncryptor.encrypt((String) value);
    }

    public void process(Map payload) {
        this.maskKeys(payload);
    }

    public void addTokenDetails(HttpServletRequest request, Map payload){
        if(null!= request.getAttribute("jwtClaims")){
            populateClaimsIntoRequest(payload,(Map<String, Object>) request.getAttribute("jwtClaims"));
        }
    }
}


//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.comviva.mfs.common.cryptography;

import org.apache.commons.lang3.StringUtils;
import org.jasypt.util.text.BasicTextEncryptor;

public class TextEncryptor {
    public static final String ENCRYPTED_VALUE_PREFIX = "enc_";
    private BasicTextEncryptor encryptor = new BasicTextEncryptor();

    public TextEncryptor(String serviceRequestId, String salt) {
        this.encryptor.setPassword(serviceRequestId + "." + salt);
    }

    public String decrypt(String encryptedValue) {
        if (encryptedValue == null) {
            return null;
        } else {
            return this.isEncrypted(encryptedValue) ? this.encryptor.decrypt(encryptedValue.substring(4)) : encryptedValue;
        }
    }

    public boolean isEncrypted(String encryptedValue) {
        return StringUtils.startsWith(encryptedValue, "enc_");
    }

    public String encrypt(String value) {
        return this.isEncrypted(value) ? value : this.doEncrypt(value);
    }

    private String doEncrypt(String value) {
        return "enc_" + this.encryptor.encrypt(value);
    }
}
