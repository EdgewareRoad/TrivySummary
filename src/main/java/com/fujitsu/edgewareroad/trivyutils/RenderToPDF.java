package com.fujitsu.edgewareroad.trivyutils;

import com.openhtmltopdf.pdfboxout.PdfRendererBuilder;
import com.openhtmltopdf.util.Diagnostic;

import java.io.File;
import java.io.OutputStream;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.jsoup.Jsoup;
import org.jsoup.helper.W3CDom;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;
import org.thymeleaf.templatemode.TemplateMode;
import org.thymeleaf.templateresolver.ClassLoaderTemplateResolver;
import org.thymeleaf.templateresolver.ITemplateResolver;
import org.w3c.dom.Document;

public class RenderToPDF {

    private Logger logger = LoggerFactory.getLogger(RenderToPDF.class);

	private TemplateEngine templateEngine = templateEngine();

	private ITemplateResolver templateResolver() {
		// SpringResourceTemplateResolver automatically integrates with Spring's own
		// resource resolution infrastructure, which is highly recommended.
		var templateResolver = new ClassLoaderTemplateResolver();
		templateResolver.setCharacterEncoding("UTF-8");
		templateResolver.setPrefix("/templates/");
		templateResolver.setSuffix(".html");
		// HTML is the default value, added here for the sake of clarity.
		templateResolver.setTemplateMode(TemplateMode.HTML);
		// Template cache is true by default. Set to false if you want
		// templates to be automatically updated when modified.
		templateResolver.setCacheable(true);
		return templateResolver;
	}

	private TemplateEngine templateEngine(){
		// SpringTemplateEngine automatically applies SpringStandardDialect and
		// enables Spring's own MessageSource message resolution mechanisms.
		var templateEngine = new TemplateEngine();
		templateEngine.setTemplateResolver(templateResolver());
		return templateEngine;
	}

    public File renderToPDF(Map<String, Object> variables, String templateName, Path outputPath) throws IOException
    {
        Path tempFolder = Files.createTempDirectory("trivyanalysis");
        Path stylesAsset = Path.of(tempFolder.toString(), "styles.css");
        try(InputStream assetStream = getClass().getResourceAsStream("/templates/styles.css"))
        {
            Files.copy(assetStream, stylesAsset);
        }

        File out = outputPath.toFile();
        try (OutputStream os = new FileOutputStream(out))
        {
            URI baseURI = tempFolder.toUri();
            String baseURIAsString = baseURI.toASCIIString();

            // For debug only
            List<Diagnostic> logs = new ArrayList<>();

            PdfRendererBuilder builder = new PdfRendererBuilder();
            builder.withDiagnosticConsumer(logs::add);
            builder.withUri(outputPath.toString());
            builder.toStream(os);
            builder.withW3cDocument(getXHTMLDocument(variables, templateName, baseURIAsString), baseURIAsString);
            builder.run();
        }
        catch(Exception ex)
        {
            logger.error(String.format("Could not write to output path '$s'.", outputPath), ex);
        }
        finally
        {
            Files.delete(stylesAsset);
            Files.delete(tempFolder);
        }
        return out;
    }

    private Document getXHTMLDocument(Map<String, Object> variables, String templateName, String baseURIAsString)
    {
        var thymeleafContext = new Context();
        for (String variableName : variables.keySet())
        {
            thymeleafContext.setVariable(variableName, variables.get(variableName));
        }

        var thymeleafResult = templateEngine.process(templateName, thymeleafContext);
        org.jsoup.nodes.Document thymeleafDocument = Jsoup.parse(thymeleafResult, baseURIAsString);
        return new W3CDom().fromJsoup(thymeleafDocument);
    }
}
