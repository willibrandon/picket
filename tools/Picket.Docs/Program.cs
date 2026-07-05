using Picket.Docs;

string repositoryRoot = DocumentationGenerator.FindRepositoryRoot(Directory.GetCurrentDirectory());
var generator = new DocumentationGenerator(repositoryRoot);
generator.Generate();
