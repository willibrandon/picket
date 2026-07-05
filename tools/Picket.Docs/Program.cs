using Picket.Docs;

if (args.Length > 1 || (args.Length == 1 && !args[0].Equals("--check", StringComparison.Ordinal)))
{
    Console.Error.WriteLine("Usage: Picket.Docs [--check]");
    return 2;
}

string repositoryRoot = DocumentationGenerator.FindRepositoryRoot(Directory.GetCurrentDirectory());
var generator = new DocumentationGenerator(repositoryRoot);
generator.Generate();

if (args.Length == 0)
{
    return 0;
}

string status = generator.GetGeneratedDocumentationStatus();
if (status.Length == 0)
{
    return 0;
}

Console.Error.WriteLine("Generated documentation is stale. Run `pnpm --dir docs-site docs:generate` and commit the result.");
Console.Error.WriteLine(status);
return 1;
