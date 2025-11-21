package com.fujitsu.edgewareroad.trivyutils.performance;

import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Aspect
@Component
public class ExecutionTimeAdvice {

    private Logger logger = LoggerFactory.getLogger(ExecutionTimeAdvice.class);

    @Around("@annotation(com.fujitsu.edgewareroad.trivyutils.performance.TrackExecutionTime)")
    public Object trackExecutionTime(org.aspectj.lang.ProceedingJoinPoint pjp) throws Throwable {
        if (logger.isInfoEnabled()) {
            long start = System.currentTimeMillis();
            Object retVal = pjp.proceed();
            long end = System.currentTimeMillis();
            logger.info("Execution time of {}::{} = {} ms", pjp.getSignature().getDeclaringTypeName(),
                    pjp.getSignature().getName(), (end - start));
            return retVal;
        }
        return pjp.proceed();
    }
}
